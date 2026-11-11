"""Run external tools so that a timeout or Ctrl+C really stops them, child processes included.

subprocess.run(timeout=...) kills only the process it started. Several tools are launchers: the standalone
capa (and anything else frozen with PyInstaller) starts a second process that does the work and holds the
memory. Killing just the launcher left that worker running orphaned, at full memory, and a few of them at
once could exhaust the machine's RAM. Every tool therefore runs in its own process group (POSIX session /
Windows process group) and the whole group is killed on timeout, interrupt or any other error.

A memory ceiling (macOS/Linux) stops a tool whose process group grows past `max_mb`, so one huge file
can't take the whole machine down either.
"""
from __future__ import annotations

import os
import signal
import subprocess
import sys
import time


class MemoryLimitExceeded(subprocess.SubprocessError):
    def __init__(self, cmd, max_mb: int, used_mb: int):
        super().__init__(f"{cmd[0]} used {used_mb} MB (limit {max_mb} MB) and was stopped")
        self.max_mb, self.used_mb = max_mb, used_mb


def group_rss_mb(pgid: int) -> int:
    """Resident memory of every process in a process group, in MB (0 if it can't be measured)."""
    try:
        out = subprocess.run(["ps", "-axo", "pgid=,rss="], capture_output=True, text=True, timeout=10).stdout
    except (OSError, subprocess.SubprocessError):
        return 0
    kb = 0
    for line in out.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[0] == str(pgid) and parts[1].isdigit():
            kb += int(parts[1])
    return kb // 1024


def _kill_group(p: subprocess.Popen) -> None:
    if p.poll() is not None and sys.platform == "win32":
        return
    try:
        if sys.platform == "win32":
            subprocess.run(["taskkill", "/T", "/F", "/PID", str(p.pid)], capture_output=True, timeout=30)
        else:
            os.killpg(p.pid, signal.SIGKILL)       # start_new_session: the group id is the child's pid
    except (OSError, subprocess.SubprocessError):
        pass
    try:
        p.kill()
    except OSError:
        pass


def run_group(cmd: list[str], timeout: float | None = None, *, capture_output: bool = True, text: bool = True,
              errors: str = "replace", cwd=None, stdin=subprocess.DEVNULL,
              max_mb: int | None = None) -> subprocess.CompletedProcess:
    """Like subprocess.run, but the tool and everything it started are killed on timeout or interruption,
    or when (with max_mb, macOS/Linux) their combined memory passes max_mb. Raises subprocess.TimeoutExpired,
    MemoryLimitExceeded or OSError."""
    kw: dict = {"cwd": cwd, "stdin": stdin}
    if capture_output:
        kw.update(stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if text:
        kw.update(text=True, errors=errors)
    if sys.platform == "win32":
        kw["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        kw["start_new_session"] = True
    p = subprocess.Popen(cmd, **kw)
    watch = bool(max_mb) and sys.platform != "win32"
    deadline = None if timeout is None else time.monotonic() + timeout
    try:
        while True:
            step = 2.0 if watch else None
            if deadline is not None:
                left = deadline - time.monotonic()
                if left <= 0:
                    raise subprocess.TimeoutExpired(cmd, timeout)
                step = min(step, left) if step else left
            try:
                out, err = p.communicate(timeout=step)
                break
            except subprocess.TimeoutExpired:
                if watch:
                    used = group_rss_mb(p.pid)
                    if used > max_mb:
                        raise MemoryLimitExceeded(cmd, max_mb, used) from None
                if deadline is not None and time.monotonic() >= deadline:
                    raise subprocess.TimeoutExpired(cmd, timeout) from None
    except BaseException:                          # TimeoutExpired, KeyboardInterrupt, anything
        _kill_group(p)
        try:
            p.communicate(timeout=10)
        except (subprocess.SubprocessError, OSError, ValueError):
            pass
        raise
    if sys.platform != "win32":
        # The tool exited; make sure nothing it left behind keeps running (e.g. a launcher that quit early).
        try:
            os.killpg(p.pid, signal.SIGKILL)
        except OSError:
            pass
    return subprocess.CompletedProcess(cmd, p.returncode, out, err)
