import os
import tempfile
from pathlib import Path, PurePosixPath

from .errors import INVALID_ARGS, REFUSED, ToolFailure

STATE_DIR = ".workspaced"
LOGS_DIR = ".logs"

_README = """\
This directory is managed by workspaced. Do not edit it by hand.

It holds per-session read hashes used to detect files changed since they were
last read. Deleting it is harmless but makes the next edit's error less precise.
"""


class Workspace:
    """The confined root; the only place a model-supplied path becomes real."""

    def __init__(self, root: Path) -> None:
        self.root = root.resolve(strict=True)
        if not self.root.is_dir():
            raise NotADirectoryError(self.root)
        self.state = self.root / STATE_DIR
        self.logs = self.root / LOGS_DIR

    def prepare(self) -> None:
        """Create the state and log directories (protocol.md §8.1)."""
        self.state.mkdir(exist_ok=True)
        self.logs.mkdir(exist_ok=True)
        (self.state / "README.md").write_text(_README)
        (self.state / ".gitignore").write_text("*\n")

    def resolve(self, raw: str, *, write: bool = False) -> Path:
        """A model-supplied path, relative or absolute, confined beneath the root."""
        if not raw or "\0" in raw:
            raise ToolFailure(INVALID_ARGS, "Path is empty or contains a NUL byte.")
        given = PurePosixPath(raw)
        if given.is_absolute():
            if not given.is_relative_to(self.root):
                raise ToolFailure(
                    REFUSED, f"{raw} is outside the workspace {self.root}."
                )
            given = given.relative_to(self.root)
        if ".." in given.parts:
            raise ToolFailure(REFUSED, f"{raw} contains '..'; use a path without it.")
        # resolve() follows symlinks already present, so a link planted inside
        # the workspace that points out of it is caught here. A link swapped in
        # between this check and the open is not: openat2 with RESOLVE_BENEATH
        # closes that, and is v0.2 (workspaced.md §5).
        real = (self.root / given).resolve()
        if not real.is_relative_to(self.root):
            raise ToolFailure(REFUSED, f"{raw} resolves outside the workspace.")
        if write and real.is_relative_to(self.state):
            raise ToolFailure(REFUSED, f"{STATE_DIR}/ is managed by workspaced.")
        return real


def write_atomic(path: Path, data: bytes) -> None:
    """Replace a file's bytes in one rename, keeping its mode."""
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        # A fresh file takes the process umask, so group-writable under 002.
        with open(path, "xb") as f:
            f.write(data)
        return
    mode = path.stat().st_mode & 0o7777
    fd, name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    tmp = Path(name)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)
