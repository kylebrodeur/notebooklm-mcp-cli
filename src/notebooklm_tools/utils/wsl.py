"""WSL2 utility functions for cross-platform authentication support.

WSL2 cannot directly launch GUI applications without causing terminal corruption.
This module provides helpers to launch Windows Chrome from WSL and manage
the cross-boundary authentication flow.
"""

import logging
import subprocess
import time
from pathlib import Path

import httpx

logger = logging.getLogger(__name__)


DEFAULT_WSL_CDP_PORT = 9222
WINDOWS_CHROME_PATHS = [
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
]


def is_wsl() -> bool:
    """Detect if running inside Windows Subsystem for Linux.

    Returns:
        True if WSL environment detected, False otherwise.
    """
    # Check for WSLInterop file (existence indicates WSL2)
    wslinterop = Path("/proc/sys/fs/binfmt_misc/WSLInterop")
    if wslinterop.exists():
        return True

    # Check kernel version string for microsoft
    try:
        version = Path("/proc/version").read_text().lower()
        return "microsoft" in version or "wsl" in version
    except (OSError, FileNotFoundError):
        pass

    return False


def get_windows_host_ip() -> str | None:
    """Get the Windows host IP address from WSL.

    WSL2 uses a virtual network where the Windows host is reachable
    via the nameserver IP in /etc/resolv.conf.

    Returns:
        IP address string (e.g., "172.20.112.1") or None if not in WSL.
    """
    if not is_wsl():
        return None

    try:
        result = subprocess.run(
            ["grep", "nameserver", "/etc/resolv.conf"],
            capture_output=True,
            text=True,
            check=True,
        )
        # Format: "nameserver 172.20.112.1"
        ip = result.stdout.strip().split()[1]
        logger.debug(f"Windows host IP from resolv.conf: {ip}")
        return ip
    except (subprocess.CalledProcessError, IndexError, FileNotFoundError) as e:
        logger.warning(f"Could not determine Windows host IP: {e}")
        return None


def find_windows_chrome() -> str | None:
    """Find Chrome executable path on Windows side from WSL.

    Searches common Chrome installation locations.

    Returns:
        Windows path (e.g., "C:\\...\\chrome.exe") or None if not found.
    """
    if not is_wsl():
        return None

    for path in WINDOWS_CHROME_PATHS:
        # Convert Windows path to WSL path (/mnt/c/...)
        wsl_path = Path("/mnt/c") / path[3:].replace("\\", "/")
        if wsl_path.exists():
            logger.debug(f"Found Windows Chrome at: {path}")
            return path

    # Fallback: Try to find via PATH
    try:
        result = subprocess.run(
            ["which", "chrome.exe"],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            windows_path = result.stdout.strip().replace("/mnt/c/", "C:\\").replace("/", "\\")
            logger.debug(f"Found Windows Chrome via PATH: {windows_path}")
            return windows_path
    except Exception as e:
        logger.debug(f"which chrome.exe failed: {e}")

    return None


def launch_windows_chrome(port: int = DEFAULT_WSL_CDP_PORT) -> subprocess.Popen:
    """Launch Chrome on Windows side from WSL.

    Args:
        port: Remote debugging port to use.

    Returns:
        subprocess.Popen handle to the Windows Chrome process.

    Raises:
        RuntimeError: If Chrome cannot be launched.
    """
    if not is_wsl():
        raise RuntimeError("Not running in WSL environment")

    chrome_path = find_windows_chrome()
    if not chrome_path:
        raise RuntimeError(
            "Chrome not found on Windows side. "
            "Common locations checked:\n  " +
            "\n  ".join(WINDOWS_CHROME_PATHS)
        )

    # Convert Windows path to WSL executable path
    # C:\Program Files\... -> /mnt/c/Program Files/...
    wsl_chrome = Path("/mnt/c") / chrome_path[3:].replace("\\", "/")

    args = [
        str(wsl_chrome),
        f"--remote-debugging-port={port}",
        "--remote-debugging-address=0.0.0.0",  # Bind to all interfaces so WSL can reach it
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-extensions",
        "--remote-allow-origins=*",  # Required for cross-origin from external IPs
    ]

    logger.info(f"Launching Windows Chrome on port {port}")
    try:
        process = subprocess.Popen(
            args,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,  # Prevent signal propagation
        )
        logger.debug(f"Chrome process started: PID {process.pid}")
        return process
    except Exception as e:
        raise RuntimeError(f"Failed to launch Chrome: {e}") from e


def wait_for_cdp(cdp_url: str, timeout: int = 30) -> bool:
    """Wait for Chrome DevTools Protocol to be ready.

    Args:
        cdp_url: Full CDP HTTP URL (e.g., "http://172.20.112.1:9222")
        timeout: Maximum seconds to wait.

    Returns:
        True if CDP is ready, False if timeout.
    """
    import urllib.parse

    parsed = urllib.parse.urlparse(cdp_url)
    base_url = f"{parsed.scheme}://{parsed.hostname}:{parsed.port}"

    logger.debug(f"Waiting for CDP at {base_url}")
    start = time.time()
    while time.time() - start < timeout:
        try:
            response = httpx.get(f"{base_url}/json", timeout=2)
            if response.status_code == 200:
                logger.debug(f"CDP ready after {time.time() - start:.1f}s")
                return True
        except Exception:
            pass
        time.sleep(0.5)

    logger.warning(f"CDP not ready after {timeout}s")
    return False


def terminate_windows_chrome(process: subprocess.Popen | None) -> bool:
    """Terminate a Windows Chrome process launched from WSL.

    Args:
        process: subprocess.Popen handle from launch_windows_chrome()

    Returns:
        True if termination was attempted, False otherwise.
    """
    if process is None:
        return False

    try:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
        logger.debug(f"Terminated Chrome process {process.pid}")
        return True
    except Exception as e:
        logger.warning(f"Failed to terminate Chrome: {e}")
        return False


def get_wsl_cdp_url(port: int = DEFAULT_WSL_CDP_PORT) -> str | None:
    """Get the CDP URL for connecting to Windows Chrome from WSL.

    Args:
        port: The port Chrome is listening on.

    Returns:
        Full CDP URL (e.g., "http://172.20.112.1:9222") or None.
    """
    ip = get_windows_host_ip()
    if not ip:
        return None
    return f"http://{ip}:{port}"
