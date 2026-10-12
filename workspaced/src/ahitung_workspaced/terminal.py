import asyncio
import contextlib
import fcntl
import os
import re
import shutil
import signal
import struct
import subprocess
import termios
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, BinaryIO

from .errors import (
    HANDLE_EVICTED,
    HANDLE_EXISTS,
    HANDLE_NOT_FOUND,
    INVALID_ARGS,
    REFUSED,
    ToolFailure,
)
from .files import INLINE_CAP_CHARS
from .paths import Workspace

# exec layer §2, §4, §8.
NAME = re.compile(r"[a-z0-9][a-z0-9_-]{0,31}")
IDLE_EVICT_S = 15 * 60
READ_TIMEOUT_DEFAULT = 2.0
READ_TIMEOUT_MAX = 30.0
MAX_HANDLES_PER_SESSION = 8
TERM_GRACE_S = 2.0
WRITE_TIMEOUT_S = 2.0
# Output keeps arriving in bursts after a command; wait this long for quiet.
SETTLE_S = 0.2
ROWS, COLS = 50, 200

KEYS: dict[str, bytes] = {
    "ESC": b"\x1b",
    "ENTER": b"\r",
    "TAB": b"\t",
    "BACKSPACE": b"\x7f",
    "UP": b"\x1b[A",
    "DOWN": b"\x1b[B",
    "RIGHT": b"\x1b[C",
    "LEFT": b"\x1b[D",
} | {f"CTRL+{chr(c)}": bytes([c - 64]) for c in range(ord("A"), ord("Z") + 1)}

# Escape sequences are removed from what the model reads, not from the log.
_ANSI = re.compile(
    rb"\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[@-_]"
)
# Control characters other than tab and newline must arrive as named keys.
_RAW_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


@dataclass
class Handle:
    name: str
    id: uuid.UUID
    proc: subprocess.Popen[bytes]
    master: int
    log_path: Path
    log: BinaryIO
    size: int = 0
    cursor: int = 0
    eof: bool = False
    last_used: float = field(default_factory=time.monotonic)
    changed: asyncio.Event = field(default_factory=asyncio.Event)

    @property
    def running(self) -> bool:
        return self.proc.poll() is None

    def summary(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "id": str(self.id),
            "running": self.running,
            "exit_code": self.proc.returncode,
            "log_path": str(self.log_path),
        }


class Terminals:
    """PTY sessions named by the model and scoped to its chat session."""

    def __init__(self, workspace: Workspace) -> None:
        self.ws = workspace
        self.handles: dict[tuple[str, str], Handle] = {}
        self.evicted: set[tuple[str, str]] = set()

    def open(self, sid: str, name: str, command: str | None) -> dict[str, Any]:
        if not NAME.fullmatch(name):
            raise ToolFailure(INVALID_ARGS, "name must match [a-z0-9][a-z0-9_-]{0,31}.")
        key = (sid, name)
        existing = self.handles.get(key)
        if existing is not None and existing.running:
            raise ToolFailure(HANDLE_EXISTS, f"Session '{name}' is already open.")
        if existing is not None:
            self._release(key)
        if sum(1 for s, _ in self.handles if s == sid) >= MAX_HANDLES_PER_SESSION:
            raise ToolFailure(
                REFUSED,
                f"{MAX_HANDLES_PER_SESSION} sessions are open; close one first.",
            )
        setsid = shutil.which("setsid")
        bash = shutil.which("bash")
        if setsid is None or bash is None:
            raise ToolFailure(REFUSED, "setsid and bash must be installed.")

        master, slave = os.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", ROWS, COLS, 0, 0))
        argv = [bash] if command is None else [bash, "-c", command]
        try:
            # setsid --ctty makes the PTY the controlling terminal, so CTRL+C
            # reaches the foreground job, without a preexec_fn, which is unsafe
            # in a process with threads.
            proc = subprocess.Popen(
                [setsid, "--ctty", *argv],
                stdin=slave,
                stdout=slave,
                stderr=slave,
                cwd=self.ws.root,
                env=os.environ | {"TERM": "xterm-256color"},
            )
        finally:
            os.close(slave)
        os.set_blocking(master, False)
        handle_id = uuid.uuid7()
        log_path = self.ws.logs / f"{handle_id}.pty.log"
        handle = Handle(name, handle_id, proc, master, log_path, open(log_path, "wb"))
        asyncio.get_running_loop().add_reader(master, self._on_output, handle)
        self.handles[key] = handle
        self.evicted.discard(key)
        return handle.summary()

    async def send(
        self,
        sid: str,
        name: str,
        text: str | None,
        keys: list[str] | None,
        read_timeout: float,
    ) -> dict[str, Any]:
        handle = self._get(sid, name)
        if not text and not keys:
            raise ToolFailure(INVALID_ARGS, "send needs text, keys, or both.")
        if text and _RAW_CONTROL.search(text):
            raise ToolFailure(
                INVALID_ARGS,
                "text contains control characters; send them as keys, "
                f"one of {sorted(KEYS)}.",
            )
        unknown = [k for k in keys or [] if k not in KEYS]
        if unknown:
            raise ToolFailure(
                INVALID_ARGS, f"Unknown keys {unknown}; allowed: {sorted(KEYS)}."
            )
        if not handle.running:
            raise ToolFailure(
                REFUSED, f"Session '{name}' has exited; read its output or close it."
            )
        payload = (text or "").encode() + b"".join(KEYS[k] for k in keys or [])
        await _write_all(handle.master, payload)
        return await self._read_new(handle, read_timeout)

    async def read(
        self, sid: str, name: str, read_timeout: float, from_byte: int | None
    ) -> dict[str, Any]:
        handle = self._get(sid, name)
        if from_byte is None:
            return await self._read_new(handle, read_timeout)
        # A re-read of an earlier region leaves the cursor where it is.
        handle.log.flush()
        with open(handle.log_path, "rb") as f:
            f.seek(from_byte)
            data = f.read(INLINE_CAP_CHARS)
        return self._result(handle, data, from_byte, from_byte + len(data), False)

    def list(self, sid: str) -> list[dict[str, Any]]:
        return [h.summary() for (s, _), h in self.handles.items() if s == sid]

    async def close(self, sid: str, name: str) -> dict[str, Any]:
        handle = self._get(sid, name)
        await _terminate(handle)
        summary = handle.summary()
        self._release((sid, name))
        return summary

    async def evict_idle(self) -> None:
        """Close sessions idle past the limit (exec layer §4)."""
        now = time.monotonic()
        for key, handle in list(self.handles.items()):
            if now - handle.last_used > IDLE_EVICT_S:
                await _terminate(handle)
                self._release(key)
                self.evicted.add(key)

    async def close_all(self) -> None:
        for key, handle in list(self.handles.items()):
            await _terminate(handle)
            self._release(key)

    def _get(self, sid: str, name: str) -> Handle:
        key = (sid, name)
        handle = self.handles.get(key)
        if handle is None:
            if key in self.evicted:
                raise ToolFailure(
                    HANDLE_EVICTED,
                    f"Session '{name}' was closed after {IDLE_EVICT_S // 60} minutes "
                    "idle. Open it again.",
                )
            raise ToolFailure(HANDLE_NOT_FOUND, f"No session named '{name}'.")
        handle.last_used = time.monotonic()
        return handle

    def _on_output(self, handle: Handle) -> None:
        try:
            data = os.read(handle.master, 65536)
        except BlockingIOError:
            return
        except OSError:
            # EIO once every process holding the PTY's other side has exited.
            data = b""
        if not data:
            asyncio.get_running_loop().remove_reader(handle.master)
            handle.eof = True
        else:
            handle.log.write(data)
            handle.size += len(data)
        handle.changed.set()

    async def _read_new(self, handle: Handle, timeout: float) -> dict[str, Any]:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        while handle.size == handle.cursor and not handle.eof:
            handle.changed.clear()
            try:
                async with asyncio.timeout_at(deadline):
                    await handle.changed.wait()
            except TimeoutError:
                break
        while not handle.eof and loop.time() < deadline:
            seen = handle.size
            handle.changed.clear()
            with contextlib.suppress(TimeoutError):
                async with asyncio.timeout(min(SETTLE_S, deadline - loop.time())):
                    await handle.changed.wait()
            if handle.size == seen:
                break
        start, end = handle.cursor, handle.size
        handle.cursor = end
        handle.log.flush()
        with open(handle.log_path, "rb") as f:
            f.seek(start)
            data = f.read(end - start)
        return self._result(handle, data, start, end, handle.eof)

    def _result(
        self, handle: Handle, data: bytes, start: int, end: int, eof: bool
    ) -> dict[str, Any]:
        text = _ANSI.sub(b"", data).decode(errors="backslashreplace")
        text = text.replace("\r\n", "\n").replace("\r", "")
        truncated = len(text) > INLINE_CAP_CHARS
        if truncated:
            edge = INLINE_CAP_CHARS // 2
            text = (
                f"{text[:edge]}\n[… elided; full output in log_path …]\n{text[-edge:]}"
            )
        return {
            **handle.summary(),
            "output": text,
            "truncated": truncated,
            "from_byte": start,
            "to_byte": end,
            "eof": eof,
        }

    def _release(self, key: tuple[str, str]) -> None:
        handle = self.handles.pop(key)
        if not handle.eof:
            asyncio.get_running_loop().remove_reader(handle.master)
        os.close(handle.master)
        handle.log.close()


async def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    deadline = time.monotonic() + WRITE_TIMEOUT_S
    while view:
        try:
            written = os.write(fd, view)
        except BlockingIOError:
            # The PTY's input buffer is full until the child reads from it.
            if time.monotonic() > deadline:
                raise ToolFailure(
                    REFUSED, "The session is not reading its input; nothing more sent."
                ) from None
            await asyncio.sleep(0.01)
            continue
        view = view[written:]


async def _terminate(handle: Handle) -> None:
    if not handle.running:
        return
    # SIGHUP first, as a closing terminal would: an interactive bash passes it
    # on to its jobs, which sit in process groups of their own.
    for sig in (signal.SIGHUP, signal.SIGTERM):
        with contextlib.suppress(ProcessLookupError):
            os.killpg(handle.proc.pid, sig)
    deadline = time.monotonic() + TERM_GRACE_S
    while handle.running and time.monotonic() < deadline:
        await asyncio.sleep(0.05)
    if handle.running:
        with contextlib.suppress(ProcessLookupError):
            os.killpg(handle.proc.pid, signal.SIGKILL)
        handle.proc.wait()
