# SPDX-License-Identifier: GPL-2.0-only
"""
Generic instrumented subprocess manager for C-SCARE monitors.

Manages a target process with stderr capture, supporting sanitizer monitoring.
"""

import os
import subprocess
import tempfile
import time
from typing import Dict, List, Optional

__all__ = ['InstrumentedProcess']

DEFAULT_ASAN_OPTIONS = 'halt_on_error=0:detect_odr_violation=0:allocator_may_return_null=1'
DEFAULT_UBSAN_OPTIONS = 'print_stacktrace=1:halt_on_error=0'


class InstrumentedProcess:
    """Manage a subprocess with stderr capture for sanitizer monitoring."""

    def __init__(self, cmd: List[str], env: Optional[Dict[str, str]] = None,
                 ready_timeout: float = 10.0):
        self._cmd = cmd
        self._user_env = env or {}
        self._ready_timeout = ready_timeout
        self._proc: Optional[subprocess.Popen] = None
        self._stderr_file = None
        self._stderr_path: Optional[str] = None
        self._read_offset = 0

    def start(self) -> None:
        """Start the process with sanitizer-friendly environment."""
        env = os.environ.copy()
        env.setdefault('ASAN_OPTIONS', DEFAULT_ASAN_OPTIONS)
        env.setdefault('UBSAN_OPTIONS', DEFAULT_UBSAN_OPTIONS)
        env.update(self._user_env)

        self._stderr_file = tempfile.NamedTemporaryFile(
            mode='w+b', prefix='cscare_stderr_', suffix='.log', delete=False
        )
        self._stderr_path = self._stderr_file.name
        self._read_offset = 0

        self._proc = subprocess.Popen(
            self._cmd,
            stdout=subprocess.DEVNULL,
            stderr=self._stderr_file,
            env=env,
        )

    def stop(self) -> int:
        """Stop the process and return its exit code."""
        if self._proc is None:
            return 0
        if self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()
                self._proc.wait()
        code = self._proc.returncode
        self._cleanup_stderr()
        return code

    def drain_log(self) -> str:
        """Read and return any new stderr output since last drain."""
        if self._stderr_path is None:
            return ''
        try:
            with open(self._stderr_path, 'r', errors='replace') as f:
                f.seek(self._read_offset)
                new_data = f.read()
                self._read_offset = f.tell()
                return new_data
        except (OSError, IOError):
            return ''

    def get_full_log(self) -> str:
        """Read the entire stderr log."""
        if self._stderr_path is None:
            return ''
        try:
            with open(self._stderr_path, 'r', errors='replace') as f:
                return f.read()
        except (OSError, IOError):
            return ''

    def is_alive(self) -> bool:
        """Check if the process is still running."""
        if self._proc is None:
            return False
        return self._proc.poll() is None

    def exit_code(self) -> Optional[int]:
        """Get exit code if process has terminated, else None."""
        if self._proc is None:
            return None
        return self._proc.poll()

    def restart(self) -> None:
        """Stop and restart the process."""
        self.stop()
        self.start()

    def _cleanup_stderr(self):
        """Close and remove the stderr temp file."""
        if self._stderr_file is not None:
            try:
                self._stderr_file.close()
            except Exception:
                pass
            self._stderr_file = None
        if self._stderr_path and os.path.exists(self._stderr_path):
            try:
                os.unlink(self._stderr_path)
            except OSError:
                pass
            self._stderr_path = None

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *exc):
        self.stop()
