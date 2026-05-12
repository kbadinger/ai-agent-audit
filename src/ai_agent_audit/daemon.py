"""Daemon management: PID file, forking, signal handling."""

from __future__ import annotations

import atexit
import logging
import os
import signal
import sys
from pathlib import Path
from typing import Optional

from .config import AUDIT_DIR, AUDIT_PID_FILE

logger = logging.getLogger(__name__)


def read_pid() -> Optional[int]:
    """Read PID from the PID file, or None if not running."""
    if not AUDIT_PID_FILE.exists():
        return None
    try:
        pid = int(AUDIT_PID_FILE.read_text().strip())
        # Check if process is actually running
        os.kill(pid, 0)
        return pid
    except (ValueError, ProcessLookupError, PermissionError):
        AUDIT_PID_FILE.unlink(missing_ok=True)
        return None


def write_pid() -> None:
    """Write current PID to the PID file."""
    AUDIT_DIR.mkdir(parents=True, exist_ok=True)
    AUDIT_PID_FILE.write_text(str(os.getpid()))
    atexit.register(lambda: AUDIT_PID_FILE.unlink(missing_ok=True))


def stop_daemon() -> bool:
    """Send SIGTERM to the running daemon. Returns True if stopped."""
    pid = read_pid()
    if pid is None:
        return False
    try:
        os.kill(pid, signal.SIGTERM)
        return True
    except ProcessLookupError:
        AUDIT_PID_FILE.unlink(missing_ok=True)
        return False


def daemonize() -> None:
    """Fork into background (Unix double-fork)."""
    if not hasattr(os, "fork"):
        print("Error: Daemon mode requires Unix (macOS/Linux). Use 'ai-agent-audit sweep' on Windows.", file=sys.stderr)
        sys.exit(1)

    # First fork
    pid = os.fork()
    if pid > 0:
        sys.exit(0)

    os.setsid()

    # Second fork
    pid = os.fork()
    if pid > 0:
        sys.exit(0)

    # Redirect stdio to /dev/null
    sys.stdout.flush()
    sys.stderr.flush()
    devnull = open(os.devnull, "r+b")
    os.dup2(devnull.fileno(), sys.stdin.fileno())
    os.dup2(devnull.fileno(), sys.stdout.fileno())
    os.dup2(devnull.fileno(), sys.stderr.fileno())
    devnull.close()


def setup_logging(foreground: bool = False) -> None:
    """Configure logging to file (and optionally console)."""
    AUDIT_DIR.mkdir(parents=True, exist_ok=True)
    log_file = AUDIT_DIR / "audit.log"

    handlers: list[logging.Handler] = [
        logging.FileHandler(log_file),
    ]
    if foreground:
        handlers.append(logging.StreamHandler())

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=handlers,
    )
