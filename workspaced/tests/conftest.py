import asyncio
import socket
import time
from collections.abc import AsyncIterator
from pathlib import Path

import pytest
import uvicorn

from ahitung_workspaced.app import build
from ahitung_workspaced.paths import Workspace

SID = "0199c4a0-0000-7000-8000-000000000001"
OTHER_SID = "0199c4a0-0000-7000-8000-000000000002"


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def workspace(tmp_path: Path) -> Workspace:
    root = tmp_path / "workspace"
    root.mkdir()
    ws = Workspace(root)
    ws.prepare()
    return ws


@pytest.fixture
async def server(workspace: Workspace) -> AsyncIterator[str]:
    """workspaced on a free localhost port, as the URL of its MCP endpoint."""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    config = uvicorn.Config(
        build(workspace).http_app(), host="127.0.0.1", port=port, log_level="warning"
    )
    instance = uvicorn.Server(config)
    task = asyncio.create_task(instance.serve())
    while not instance.started:
        await asyncio.sleep(0.02)
    yield f"http://127.0.0.1:{port}/mcp"
    instance.should_exit = True
    await task


async def wait_gone(pid: int, timeout: float = 5.0) -> bool:
    """Whether the process exits within the timeout; an unreaped zombie counts."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            state = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[0]
        except FileNotFoundError:
            return True
        if state == "Z":
            return True
        # Yield rather than block: the loop must run for children to be reaped
        # and, in the HTTP tests, for the server to see the disconnect.
        await asyncio.sleep(0.05)
    return False
