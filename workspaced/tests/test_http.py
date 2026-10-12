import asyncio
from pathlib import Path

import httpx2
import pytest
from conftest import SID, wait_gone
from fastmcp import Client
from fastmcp.client.transports import StreamableHttpTransport

from ahitung_workspaced.paths import Workspace

pytestmark = pytest.mark.anyio

PROTOCOL = "2026-07-28"


def _client(url: str, headers: dict[str, str] | None = None) -> Client:
    return Client(StreamableHttpTransport(url, headers=headers or {}))


async def test_missing_session_header_is_refused(server: str) -> None:
    async with _client(server) as client:
        result = await client.call_tool("list_dir", {}, raise_on_error=False)
    assert result.is_error is True
    assert result.structured_content["code"] == "tool.refused"


async def test_read_then_edit_over_http(server: str, workspace: Workspace) -> None:
    (workspace.root / "f.txt").write_text("hello\n")
    async with _client(server, {"X-Ahit-Session-Id": SID}) as client:
        read = await client.call_tool("read_file", {"path": "f.txt"})
        assert read.structured_content["content"] == "     1\thello\n"
        await client.call_tool(
            "edit_file", {"path": "f.txt", "old_str": "hello", "new_str": "bye"}
        )
        (workspace.root / "f.txt").write_text("changed\n")
        stale = await client.call_tool(
            "edit_file",
            {"path": "f.txt", "old_str": "changed", "new_str": "x"},
            raise_on_error=False,
        )
    assert stale.is_error is True
    assert stale.structured_content["code"] == "file.changed_since_read"


async def test_failing_command_is_not_a_tool_error(server: str) -> None:
    async with _client(server, {"X-Ahit-Session-Id": SID}) as client:
        result = await client.call_tool("run_bash", {"command": "false"})
    assert result.is_error is False
    assert result.structured_content["exit_code"] == 1


async def test_client_disconnect_kills_the_running_command(
    server: str, workspace: Workspace
) -> None:
    body = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "run_bash",
            "arguments": {"command": "echo $$ > me.pid; sleep 60", "kill_after": 120},
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": PROTOCOL,
                "io.modelcontextprotocol/clientCapabilities": {},
            },
        },
    }
    headers = {
        "Accept": "application/json, text/event-stream",
        "MCP-Protocol-Version": PROTOCOL,
        "Mcp-Method": "tools/call",
        "Mcp-Name": "run_bash",
        "X-Ahit-Session-Id": SID,
    }
    pid_file: Path = workspace.root / "me.pid"

    async def call() -> None:
        async with httpx2.AsyncClient(timeout=120) as http:
            await http.post(server, json=body, headers=headers)

    task = asyncio.create_task(call())
    async with asyncio.timeout(10):
        while not pid_file.exists() or not pid_file.read_text():
            assert not task.done(), "the call ended before the command started"
            await asyncio.sleep(0.05)
    # Cancelling the request closes its connection, which is how a cancelled
    # turn reaches workspaced under this MCP revision (workspaced.md §1.5).
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert await wait_gone(int(pid_file.read_text()))


async def test_healthz_is_plain_http(server: str) -> None:
    async with httpx2.AsyncClient() as http:
        response = await http.get(server.removesuffix("/mcp") + "/healthz")
    assert response.status_code == 200
    assert response.json()["terminals"] == 0
