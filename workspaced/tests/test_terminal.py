import asyncio
import time

import pytest
from conftest import OTHER_SID, SID

from ahitung_workspaced import terminal
from ahitung_workspaced.errors import (
    HANDLE_EVICTED,
    HANDLE_EXISTS,
    HANDLE_NOT_FOUND,
    INVALID_ARGS,
    ToolFailure,
)
from ahitung_workspaced.paths import Workspace
from ahitung_workspaced.terminal import Terminals

pytestmark = pytest.mark.anyio


@pytest.fixture
async def terminals(workspace: Workspace):
    t = Terminals(workspace)
    yield t
    await t.close_all()


async def _fails(coro) -> ToolFailure:
    with pytest.raises(ToolFailure) as caught:
        await coro
    return caught.value


async def _until(terminals: Terminals, name: str, text: str, seen: str = "") -> str:
    """Read until text appears in the output accumulated so far."""
    deadline = time.monotonic() + 10
    while text not in seen and time.monotonic() < deadline:
        seen += (await terminals.read(SID, name, 1.0, None))["output"]
    assert text in seen
    return seen


async def test_send_runs_a_command_and_returns_its_output(terminals: Terminals) -> None:
    opened = terminals.open(SID, "sh", None)
    assert opened["running"] is True
    result = await terminals.send(SID, "sh", "echo $((6*7))", ["ENTER"], 5.0)
    output = await _until(terminals, "sh", "42", result["output"])
    assert "\x1b" not in output and "\r" not in output


async def test_state_persists_between_sends(terminals: Terminals) -> None:
    terminals.open(SID, "sh", None)
    await terminals.send(SID, "sh", "cd /tmp && X=kept", ["ENTER"], 1.0)
    result = await terminals.send(SID, "sh", "echo $PWD $X", ["ENTER"], 1.0)
    await _until(terminals, "sh", "/tmp kept", result["output"])


async def test_ctrl_c_interrupts_the_foreground_job(terminals: Terminals) -> None:
    terminals.open(SID, "sh", None)
    await terminals.send(SID, "sh", "sleep 30; echo slept", ["ENTER"], 0.5)
    await terminals.send(SID, "sh", None, ["CTRL+C"], 0.5)
    result = await terminals.send(SID, "sh", "echo after", ["ENTER"], 1.0)
    output = await _until(terminals, "sh", "after", result["output"])
    assert "slept" not in output


async def test_open_on_a_live_name_fails(terminals: Terminals) -> None:
    terminals.open(SID, "sh", None)
    with pytest.raises(ToolFailure) as caught:
        terminals.open(SID, "sh", None)
    assert caught.value.code == HANDLE_EXISTS


async def test_names_are_scoped_to_the_session(terminals: Terminals) -> None:
    terminals.open(SID, "sh", None)
    terminals.open(OTHER_SID, "sh", None)
    assert [h["name"] for h in terminals.list(SID)] == ["sh"]
    failure = await _fails(terminals.read(OTHER_SID, "nope", 0.1, None))
    assert failure.code == HANDLE_NOT_FOUND


async def test_invalid_names_and_raw_escapes_are_rejected(terminals: Terminals) -> None:
    with pytest.raises(ToolFailure) as caught:
        terminals.open(SID, "Bad Name", None)
    assert caught.value.code == INVALID_ARGS
    terminals.open(SID, "sh", None)
    failure = await _fails(terminals.send(SID, "sh", "\x1b[2J", None, 0.1))
    assert failure.code == INVALID_ARGS
    failure = await _fails(terminals.send(SID, "sh", None, ["F13"], 0.1))
    assert failure.code == INVALID_ARGS


async def test_read_timeout_returns_while_the_process_runs(
    terminals: Terminals,
) -> None:
    terminals.open(SID, "srv", "sleep 30")
    result = await terminals.read(SID, "srv", 0.3, None)
    assert (
        result["output"] == "" and result["running"] is True and result["eof"] is False
    )


async def test_exit_is_distinguishable_from_no_output(terminals: Terminals) -> None:
    terminals.open(SID, "once", "echo done")
    output = ""
    for _ in range(20):
        result = await terminals.read(SID, "once", 0.5, None)
        output += result["output"]
        if result["eof"]:
            break
    assert "done" in output
    assert result["eof"] is True
    await asyncio.sleep(0.1)
    assert terminals.list(SID)[0]["running"] is False


async def test_from_byte_rereads_without_moving_the_cursor(
    terminals: Terminals,
) -> None:
    terminals.open(SID, "once", "echo first")
    await _until(terminals, "once", "first")
    again = await terminals.read(SID, "once", 0.1, 0)
    assert "first" in again["output"]
    after = await terminals.read(SID, "once", 0.2, None)
    assert "first" not in after["output"]


async def test_idle_session_is_evicted_and_says_so(
    terminals: Terminals, monkeypatch: pytest.MonkeyPatch
) -> None:
    terminals.open(SID, "sh", None)
    monkeypatch.setattr(terminal, "IDLE_EVICT_S", 0)
    await asyncio.sleep(0.01)
    await terminals.evict_idle()
    failure = await _fails(terminals.read(SID, "sh", 0.1, None))
    assert failure.code == HANDLE_EVICTED
    terminals.open(SID, "sh", None)


async def test_close_terminates_and_frees_the_name(terminals: Terminals) -> None:
    terminals.open(SID, "srv", "sleep 30")
    closed = await terminals.close(SID, "srv")
    assert closed["running"] is False
    assert terminals.list(SID) == []
    terminals.open(SID, "srv", "sleep 30")
