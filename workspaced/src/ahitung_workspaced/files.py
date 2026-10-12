import difflib
import hashlib
import json
import re
import stat
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .errors import (
    CHANGED_SINCE_READ,
    FILE_NOT_FOUND,
    INVALID_ARGS,
    PATCH_AMBIGUOUS,
    PATCH_INVALID_BYTES,
    PATCH_NO_MATCH,
    REFUSED,
    ToolFailure,
)
from .paths import Workspace, write_atomic

# design.md §11.4: the character cap on any inline result, and the line window.
INLINE_CAP_CHARS = 3840
READ_WINDOW_LINES = 300
# Above this, reading the whole file to hash it costs more than a read is worth.
MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_LIST_ENTRIES = 200

_LINE_PREFIX = re.compile(r"^\s*\d+\t")
_ESCAPED_BYTE = re.compile(r"\\x[0-9a-fA-F]{2}")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class ReadHashes:
    """Content hash at each session's last read of each path (protocol.md §6.5)."""

    def __init__(self, workspace: Workspace) -> None:
        self._dir = workspace.state / "reads"
        self._root = workspace.root
        self._lock = threading.Lock()

    def get(self, sid: str, path: Path) -> str | None:
        with self._lock:
            return self._load(sid).get(str(path.relative_to(self._root)))

    def put(self, sid: str, path: Path, digest: str) -> None:
        with self._lock:
            entries = self._load(sid)
            entries[str(path.relative_to(self._root))] = digest
            self._dir.mkdir(parents=True, exist_ok=True)
            write_atomic(self._dir / f"{sid}.json", json.dumps(entries).encode())

    def _load(self, sid: str) -> dict[str, str]:
        file = self._dir / f"{sid}.json"
        if not file.exists():
            return {}
        return json.loads(file.read_bytes())


class Files:
    def __init__(self, workspace: Workspace) -> None:
        self.ws = workspace
        self.hashes = ReadHashes(workspace)

    def read_file(self, sid: str, path: str, start: int, limit: int) -> dict[str, Any]:
        target = self.ws.resolve(path)
        data = self._read_bytes(target, path)
        digest = sha256(data)
        self.hashes.put(sid, target, digest)

        lines = data.split(b"\n")
        if lines[-1] == b"":
            lines.pop()
        total = len(lines)
        if total == 0:
            return _read_result(target, "", 0, 0, 0, False, digest, False)
        if start > total:
            raise ToolFailure(INVALID_ARGS, f"{path} has {total} lines; start={start}.")

        shown: list[str] = []
        used = 0
        invalid = False
        cut = False
        end = start - 1
        for number in range(start, min(start + limit, total + 1)):
            raw = lines[number - 1]
            text, bad = _render(raw)
            invalid |= bad
            row = f"{number:>6}\t{text}\n"
            if used + len(row) > INLINE_CAP_CHARS:
                if not shown:
                    # A single line longer than the cap: show what fits of it.
                    shown.append(row[:INLINE_CAP_CHARS])
                    end = number
                    cut = True
                break
            shown.append(row)
            used += len(row)
            end = number
        return _read_result(
            target,
            "".join(shown),
            start,
            end,
            total,
            cut or end < total,
            digest,
            invalid,
        )

    def write_file(
        self, sid: str, path: str, content: str, overwrite: bool
    ) -> dict[str, Any]:
        target = self.ws.resolve(path, write=True)
        created = not target.exists()
        if not created:
            if target.is_dir():
                raise ToolFailure(INVALID_ARGS, f"{path} is a directory.")
            if not overwrite:
                raise ToolFailure(
                    REFUSED,
                    f"{path} exists. Pass overwrite=true to replace it, "
                    "or use edit_file.",
                )
            self._check_unchanged(sid, target, path, self._read_bytes(target, path))
        data = content.encode()
        write_atomic(target, data)
        digest = sha256(data)
        self.hashes.put(sid, target, digest)
        return {
            "path": str(target),
            "bytes": len(data),
            "sha256": digest,
            "created": created,
        }

    def edit_file(
        self, sid: str, path: str, old_str: str, new_str: str
    ) -> dict[str, Any]:
        if not old_str:
            raise ToolFailure(
                INVALID_ARGS, "old_str is empty; use insert_file to add text."
            )
        if old_str == new_str:
            raise ToolFailure(INVALID_ARGS, "old_str and new_str are identical.")
        target = self.ws.resolve(path, write=True)
        data = self._read_bytes(target, path)
        self._check_unchanged(sid, target, path, data)

        old = old_str.encode()
        if data.count(old) == 0:
            stripped = _strip_line_prefixes(old_str)
            if stripped is not None and data.count(stripped.encode()) > 0:
                old = stripped.encode()
        count = data.count(old)
        if count == 0:
            raise _no_match(data, old_str, path)
        if count > 1:
            lines = _match_lines(data, old)
            raise ToolFailure(
                PATCH_AMBIGUOUS,
                f"old_str matches {count} times in {path}, at lines {lines}. "
                "Include more surrounding text so it matches once.",
                count=count,
                lines=lines,
            )
        at = data.index(old)
        updated = data[:at] + new_str.encode() + data[at + len(old) :]
        write_atomic(target, updated)
        digest = sha256(updated)
        self.hashes.put(sid, target, digest)
        return {
            "path": str(target),
            "sha256": digest,
            "replaced_at_line": data.count(b"\n", 0, at) + 1,
        }

    def insert_file(
        self, sid: str, path: str, line: int, content: str
    ) -> dict[str, Any]:
        target = self.ws.resolve(path, write=True)
        data = self._read_bytes(target, path)
        self._check_unchanged(sid, target, path, data)
        starts = [0] + [
            m.end() for m in re.finditer(b"\n", data) if m.end() < len(data)
        ]
        total = len(starts) if data else 0
        if line > total + 1:
            raise ToolFailure(
                INVALID_ARGS, f"{path} has {total} lines; line may be 1 to {total + 1}."
            )
        at = starts[line - 1] if line <= total else len(data)
        updated = data[:at] + content.encode() + data[at:]
        write_atomic(target, updated)
        digest = sha256(updated)
        self.hashes.put(sid, target, digest)
        return {"path": str(target), "sha256": digest, "inserted_at_line": line}

    def list_dir(self, path: str, depth: int) -> dict[str, Any]:
        target = self.ws.resolve(path)
        if not target.exists():
            raise ToolFailure(FILE_NOT_FOUND, f"{path} does not exist.")
        if not target.is_dir():
            raise ToolFailure(
                INVALID_ARGS, f"{path} is not a directory; use read_file."
            )
        entries: list[dict[str, Any]] = []
        truncated = self._walk(target, target, depth, entries)
        return {"path": str(target), "entries": entries, "truncated": truncated}

    def _walk(
        self, base: Path, current: Path, depth: int, out: list[dict[str, Any]]
    ) -> bool:
        for child in sorted(current.iterdir(), key=lambda p: p.name):
            if child == self.ws.state:
                continue
            if len(out) == MAX_LIST_ENTRIES:
                return True
            info = child.lstat()
            kind = _kind(info.st_mode)
            out.append(
                {
                    "name": str(child.relative_to(base)),
                    "type": kind,
                    "size": info.st_size,
                    "mtime": datetime.fromtimestamp(info.st_mtime, UTC).isoformat(),
                }
            )
            # Symlinked directories are listed, not entered, so a link cannot
            # walk the listing out of the workspace.
            if kind == "dir" and depth > 1 and self._walk(base, child, depth - 1, out):
                return True
        return False

    def _read_bytes(self, target: Path, path: str) -> bytes:
        if not target.exists():
            raise ToolFailure(FILE_NOT_FOUND, f"{path} does not exist.")
        if target.is_dir():
            raise ToolFailure(INVALID_ARGS, f"{path} is a directory; use list_dir.")
        size = target.stat().st_size
        if size > MAX_FILE_BYTES:
            raise ToolFailure(
                REFUSED,
                f"{path} is {size} bytes, over the {MAX_FILE_BYTES}-byte limit. "
                "Use run_bash with head, tail, grep, or sed.",
            )
        return target.read_bytes()

    def _check_unchanged(self, sid: str, target: Path, path: str, data: bytes) -> None:
        recorded = self.hashes.get(sid, target)
        if recorded is not None and recorded != sha256(data):
            raise ToolFailure(
                CHANGED_SINCE_READ,
                f"{path} changed since this session last read it. "
                "Read it again before editing.",
            )


def _read_result(
    target: Path,
    content: str,
    start: int,
    end: int,
    total: int,
    truncated: bool,
    digest: str,
    invalid: bool,
) -> dict[str, Any]:
    return {
        "path": str(target),
        "content": content,
        "start": start,
        "end": end,
        "total_lines": total,
        "truncated": truncated,
        "sha256": digest,
        "invalid_bytes": invalid,
    }


def _render(raw: bytes) -> tuple[str, bool]:
    """A line as text, undecodable bytes shown as \\xNN, and whether any were."""
    try:
        return raw.decode(), False
    except UnicodeDecodeError:
        return raw.decode(errors="backslashreplace"), True


def _strip_line_prefixes(text: str) -> str | None:
    """old_str with read_file's line-number prefixes removed, if every line has one."""
    lines = text.split("\n")
    if not all(_LINE_PREFIX.match(line) for line in lines if line):
        return None
    return "\n".join(_LINE_PREFIX.sub("", line, count=1) for line in lines)


def _match_lines(data: bytes, needle: bytes) -> list[int]:
    lines, at = [], data.find(needle)
    while at != -1:
        lines.append(data.count(b"\n", 0, at) + 1)
        at = data.find(needle, at + 1)
    return lines


def _no_match(data: bytes, old_str: str, path: str) -> ToolFailure:
    text = data.decode(errors="backslashreplace")
    if _ESCAPED_BYTE.search(old_str) and text != data.decode(errors="ignore"):
        return ToolFailure(
            PATCH_INVALID_BYTES,
            f"old_str contains \\xNN escapes, and {path} holds undecodable bytes. "
            "The escapes are display only; target nearby clean text, "
            "or edit with run_bash.",
        )
    hint = ""
    if "\r\n" in text and "\r" not in old_str and old_str.replace("\n", "\r\n") in text:
        hint = (
            " The file uses CRLF line endings; "
            "old_str must include \\r before each \\n."
        )
    else:
        first = next((line for line in old_str.split("\n") if line.strip()), "")
        file_lines = text.split("\n")
        close = difflib.get_close_matches(first, file_lines, n=1, cutoff=0.6)
        if close:
            hint = f" Closest line is {file_lines.index(close[0]) + 1}: {close[0]!r}."
    return ToolFailure(PATCH_NO_MATCH, f"old_str not found in {path}.{hint}")


def _kind(mode: int) -> str:
    if stat.S_ISLNK(mode):
        return "symlink"
    if stat.S_ISDIR(mode):
        return "dir"
    if stat.S_ISREG(mode):
        return "file"
    return "other"
