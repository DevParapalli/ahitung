import asyncio
import contextlib
import os
import shutil
import signal
import time
import uuid
from collections.abc import AsyncIterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from .errors import REFUSED, TIMEOUT, ToolFailure
from .files import INLINE_CAP_CHARS
from .paths import Workspace

# exec layer §4: model-supplied values are hints, clamped to this.
KILL_AFTER_DEFAULT = 30
KILL_AFTER_MAX = 300
TERM_GRACE_S = 2.0
# Each stream gets half the inline cap, split evenly between head and tail.
STREAM_EDGE = INLINE_CAP_CHARS // 4

Stream = Literal["stdout", "stderr"]


@dataclass(frozen=True)
class Chunk:
    stream: Stream
    data: bytes


@dataclass(frozen=True)
class Exit:
    code: int
    timed_out: bool


async def run(
    argv: list[str],
    cwd: Path,
    log_path: Path,
    kill_after: float,
    env: dict[str, str] | None = None,
) -> AsyncIterator[Chunk | Exit]:
    """Run a child, yielding its output as it arrives and then its exit.

    A generator rather than a buffered call so that streaming tool.output.delta
    later changes the transport only (workspaced.md G7). Closing the generator
    early, as a cancelled request does, kills the child's process group.
    """
    proc = await asyncio.create_subprocess_exec(
        *argv,
        cwd=cwd,
        env=env,
        stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        start_new_session=True,
    )
    queue: asyncio.Queue[Chunk | None] = asyncio.Queue()

    async def pump(reader: asyncio.StreamReader, stream: Stream) -> None:
        while data := await reader.read(65536):
            await queue.put(Chunk(stream, data))
        await queue.put(None)

    assert proc.stdout is not None and proc.stderr is not None
    pumps = [
        asyncio.create_task(pump(proc.stdout, "stdout")),
        asyncio.create_task(pump(proc.stderr, "stderr")),
    ]
    deadline = asyncio.get_running_loop().time() + kill_after
    timed_out = False
    try:
        with open(log_path, "wb") as log:
            open_streams = 2
            while open_streams:
                try:
                    async with asyncio.timeout_at(deadline):
                        item = await queue.get()
                except TimeoutError:
                    timed_out = True
                    break
                if item is None:
                    open_streams -= 1
                    continue
                log.write(item.data)
                yield item
        if timed_out:
            await _terminate(proc)
        else:
            # Both pipes closed but the child may still be running, having
            # closed them itself; the deadline still applies.
            try:
                async with asyncio.timeout_at(deadline):
                    await proc.wait()
            except TimeoutError:
                timed_out = True
                await _terminate(proc)
        assert proc.returncode is not None
        yield Exit(proc.returncode, timed_out)
    finally:
        if proc.returncode is None:
            _signal_group(proc.pid, signal.SIGKILL)
        for task in pumps:
            task.cancel()


async def _terminate(proc: asyncio.subprocess.Process) -> None:
    _signal_group(proc.pid, signal.SIGTERM)
    try:
        await asyncio.wait_for(proc.wait(), TERM_GRACE_S)
    except TimeoutError:
        _signal_group(proc.pid, signal.SIGKILL)
        await proc.wait()


def _signal_group(pgid: int, sig: signal.Signals) -> None:
    # The group may already be gone; that is the outcome wanted.
    with contextlib.suppress(ProcessLookupError):
        os.killpg(pgid, sig)


class Capture:
    """Head and tail of one stream, and its total size."""

    def __init__(self, edge: int) -> None:
        self.edge = edge
        self.head = bytearray()
        self.tail = bytearray()
        self.total = 0

    def add(self, data: bytes) -> None:
        self.total += len(data)
        room = self.edge - len(self.head)
        if room > 0:
            self.head += data[:room]
            data = data[room:]
        self.tail += data
        del self.tail[: max(0, len(self.tail) - self.edge)]

    @property
    def truncated(self) -> bool:
        return self.total > len(self.head) + len(self.tail)

    def text(self) -> str:
        head = self.head.decode(errors="backslashreplace")
        tail = self.tail.decode(errors="backslashreplace")
        if not self.truncated:
            return head + tail
        elided = self.total - len(self.head) - len(self.tail)
        return f"{head}\n[… {elided} bytes elided; full output in log_path …]\n{tail}"


_LANGUAGES = {
    "bash": ("bash", ".sh"),
    "python": ("python3", ".py"),
    "js": ("node", ".js"),
}


class Exec:
    def __init__(self, workspace: Workspace) -> None:
        self.ws = workspace

    async def run(
        self, language: Literal["bash", "python", "js"], source: str, kill_after: int
    ) -> dict[str, Any]:
        interpreter, suffix = _LANGUAGES[language]
        binary = shutil.which(interpreter)
        if binary is None:
            raise ToolFailure(
                REFUSED, f"{interpreter} is not installed in this workspace."
            )
        run_id = uuid.uuid7()
        # Source is kept beside its log so a traceback names a file that exists
        # (design.md §7.6).
        source_path = self.ws.logs / f"{run_id}{suffix}"
        log_path = self.ws.logs / f"{run_id}.log"
        source_path.write_text(source)

        out, err = Capture(STREAM_EDGE), Capture(STREAM_EDGE)
        started = time.monotonic()
        exit_: Exit | None = None
        argv = [binary, str(source_path)]
        env = dict(os.environ)
        if language == "python":
            # The script's own directory, .logs/, is what Python puts first on
            # sys.path; the workspace is what the model expects to import from.
            env["PYTHONPATH"] = os.pathsep.join(
                p for p in (str(self.ws.root), env.get("PYTHONPATH")) if p
            )
        events = run(argv, self.ws.root, log_path, kill_after, env)
        async with contextlib.aclosing(events):
            async for event in events:
                match event:
                    case Chunk("stdout", data):
                        out.add(data)
                    case Chunk("stderr", data):
                        err.add(data)
                    case Exit():
                        exit_ = event
        assert exit_ is not None
        result = {
            "exit_code": exit_.code,
            "stdout": out.text(),
            "stderr": err.text(),
            "stdout_bytes": out.total,
            "stderr_bytes": err.total,
            "truncated": out.truncated or err.truncated,
            "duration_ms": round((time.monotonic() - started) * 1000),
            "log_path": str(log_path),
            "source_path": str(source_path),
        }
        if exit_.timed_out:
            raise ToolFailure(
                TIMEOUT,
                f"Killed after {kill_after}s. Partial output is below and in "
                f"{log_path}. For a long-running process use bash_session.\n"
                f"stdout:\n{result['stdout']}\nstderr:\n{result['stderr']}",
                **result,
            )
        return result
