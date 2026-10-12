import asyncio
import contextlib
import os
import sys
import time
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Annotated, Any, Literal

import uvicorn
from fastmcp import FastMCP
from pydantic import Field
from starlette.requests import Request
from starlette.responses import JSONResponse

from .errors import INVALID_ARGS, ToolFailure, tool_errors
from .exec import KILL_AFTER_DEFAULT, KILL_AFTER_MAX, Exec
from .files import READ_WINDOW_LINES, Files
from .paths import STATE_DIR, Workspace
from .session import session_id
from .terminal import KEYS, READ_TIMEOUT_DEFAULT, READ_TIMEOUT_MAX, Terminals

EVICT_SWEEP_S = 60

KillAfter = Annotated[
    int,
    Field(
        ge=1,
        le=KILL_AFTER_MAX,
        description="Seconds before the process is killed. Use bash_session for "
        "anything that should keep running.",
    ),
]


def build(workspace: Workspace) -> FastMCP:
    files = Files(workspace)
    execs = Exec(workspace)
    terminals = Terminals(workspace)
    root = workspace.root
    started = time.monotonic()

    @contextlib.asynccontextmanager
    async def lifespan(_: FastMCP) -> AsyncIterator[None]:
        async def sweep() -> None:
            while True:
                await asyncio.sleep(EVICT_SWEEP_S)
                await terminals.evict_idle()

        task = asyncio.create_task(sweep())
        try:
            yield
        finally:
            task.cancel()
            await terminals.close_all()

    mcp = FastMCP(
        "workspaced",
        instructions=(
            f"Tools for the workspace at {root}. Paths may be absolute under {root} or "
            f"relative to it. Every command runs with cwd {root}; nothing carries over "
            f"between calls except files. Do not read or modify {root}/{STATE_DIR}/."
        ),
        strict_input_validation=True,
        lifespan=lifespan,
    )

    @mcp.tool(
        description=(
            "Read a window of a text file, with each line prefixed by its number and "
            "a tab. The prefixes are display only; do not include them in edits. "
            "Bytes that are not valid UTF-8 are shown as \\xNN and flagged by "
            "invalid_bytes. Reading records the file's hash, so a later edit_file "
            "fails if the file changed in between."
        )
    )
    @tool_errors
    def read_file(
        path: str,
        start: Annotated[int, Field(ge=1, description="First line, from 1.")] = 1,
        limit: Annotated[int, Field(ge=1, le=READ_WINDOW_LINES)] = READ_WINDOW_LINES,
    ) -> dict[str, Any]:
        return files.read_file(session_id(), path, start, limit)

    @mcp.tool(
        description=(
            "Create a file with exactly the given content, creating parent "
            "directories. Refuses an existing file unless overwrite is true. Bytes "
            "are written as given: no newline is added and line endings are kept."
        )
    )
    @tool_errors
    def write_file(path: str, content: str, overwrite: bool = False) -> dict[str, Any]:
        return files.write_file(session_id(), path, content, overwrite)

    @mcp.tool(
        description=(
            "Replace the one occurrence of old_str with new_str. old_str must match "
            "the file byte for byte, including whitespace and line endings, and must "
            "occur exactly once; include surrounding lines to make it unique. Fails "
            "with file.changed_since_read if the file changed since you last read it."
        )
    )
    @tool_errors
    def edit_file(path: str, old_str: str, new_str: str) -> dict[str, Any]:
        return files.edit_file(session_id(), path, old_str, new_str)

    @mcp.tool(
        description=(
            "Insert content before the given line; line = total lines + 1 appends. "
            "Content is inserted verbatim, so end it with a newline to keep it on "
            "lines of its own."
        )
    )
    @tool_errors
    def insert_file(
        path: str, line: Annotated[int, Field(ge=1)], content: str
    ) -> dict[str, Any]:
        return files.insert_file(session_id(), path, line, content)

    @mcp.tool(
        description=(
            "List a directory, recursing to the given depth. Symlinks are listed, "
            "not followed. At most 200 entries."
        )
    )
    @tool_errors
    def list_dir(
        path: str = ".", depth: Annotated[int, Field(ge=1, le=5)] = 1
    ) -> dict[str, Any]:
        session_id()
        return files.list_dir(path, depth)

    @mcp.tool(
        description=(
            f"Run a bash script and wait for it. cwd is {root}; a cd does not carry "
            "over to the next call. A non-zero exit is a normal result, not an "
            "error. stdout and stderr are returned head and tail; the full output is "
            "at log_path, readable with read_file."
        )
    )
    @tool_errors
    async def run_bash(
        command: str, kill_after: KillAfter = KILL_AFTER_DEFAULT
    ) -> dict[str, Any]:
        session_id()
        return await execs.run("bash", command, kill_after)

    @mcp.tool(
        description=(
            f"Run Python 3 code as a script and wait for it. cwd is {root}, which is "
            "also importable. Output is returned as for run_bash."
        )
    )
    @tool_errors
    async def run_python(
        code: str, kill_after: KillAfter = KILL_AFTER_DEFAULT
    ) -> dict[str, Any]:
        session_id()
        return await execs.run("python", code, kill_after)

    @mcp.tool(
        description=(
            f"Run JavaScript with Node and wait for it. cwd is {root}. Output is "
            "returned as for run_bash."
        )
    )
    @tool_errors
    async def run_js(
        code: str, kill_after: KillAfter = KILL_AFTER_DEFAULT
    ) -> dict[str, Any]:
        session_id()
        return await execs.run("js", code, kill_after)

    @mcp.tool(
        description=(
            "An interactive terminal that keeps running between calls, for servers, "
            "REPLs, and interactive programs. Output is one merged stream. Actions: "
            "open (name, optional command, else bash), send (text and/or keys, then "
            "returns new output), read (new output since the last read, or from "
            "from_byte without moving the cursor), list, close. read_timeout only "
            "bounds how long a call waits; the process keeps running. Sessions idle "
            f"for 15 minutes are closed. Keys: {', '.join(sorted(KEYS))}."
        )
    )
    @tool_errors
    async def bash_session(
        action: Literal["open", "send", "read", "list", "close"],
        name: str | None = None,
        command: str | None = None,
        text: str | None = None,
        keys: list[str] | None = None,
        read_timeout: Annotated[
            float, Field(gt=0, le=READ_TIMEOUT_MAX)
        ] = READ_TIMEOUT_DEFAULT,
        from_byte: Annotated[int, Field(ge=0)] | None = None,
    ) -> dict[str, Any]:
        sid = session_id()
        if action == "list":
            return {"sessions": terminals.list(sid)}
        if name is None:
            raise ToolFailure(INVALID_ARGS, f"{action} needs a name.")
        match action:
            case "open":
                return terminals.open(sid, name, command)
            case "send":
                return await terminals.send(sid, name, text, keys, read_timeout)
            case "read":
                return await terminals.read(sid, name, read_timeout, from_byte)
            case "close":
                return await terminals.close(sid, name)

    @mcp.custom_route("/healthz", methods=["GET"])
    async def healthz(_: Request) -> JSONResponse:
        # For the unit's health check, which speaks plain HTTP, not MCP (G6).
        return JSONResponse(
            {
                "pid": os.getpid(),
                "uptime_s": round(time.monotonic() - started),
                "root": str(root),
                "terminals": len(terminals.handles),
            }
        )

    return mcp


def main() -> None:
    root = os.environ.get("AHITUNG_WORKSPACE_ROOT")
    if not root:
        sys.exit("AHITUNG_WORKSPACE_ROOT is not set.")
    workspace = Workspace(Path(root))
    workspace.prepare()
    uvicorn.run(
        build(workspace).http_app(),
        host=os.environ.get("AHITUNG_WORKSPACED_HOST", "127.0.0.1"),
        port=int(os.environ.get("AHITUNG_WORKSPACED_PORT", "7401")),
    )
