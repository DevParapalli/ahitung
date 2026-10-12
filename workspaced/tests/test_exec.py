import asyncio
import shutil
from pathlib import Path

import pytest
from conftest import wait_gone

from ahitung_workspaced.errors import TIMEOUT, ToolFailure
from ahitung_workspaced.exec import STREAM_EDGE, Exec
from ahitung_workspaced.paths import Workspace

pytestmark = pytest.mark.anyio


@pytest.fixture
def execs(workspace: Workspace) -> Exec:
    return Exec(workspace)


async def test_nonzero_exit_is_a_result_with_streams_apart(execs: Exec) -> None:
    result = await execs.run("bash", "echo out; echo err >&2; exit 3", 10)
    assert result["exit_code"] == 3
    assert result["stdout"] == "out\n"
    assert result["stderr"] == "err\n"
    assert result["truncated"] is False


async def test_runs_in_the_workspace_and_logs_everything(
    workspace: Workspace, execs: Exec
) -> None:
    result = await execs.run("bash", "pwd; seq 1 20000", 10)
    assert result["stdout"].startswith(f"{workspace.root}\n1\n")
    assert result["stdout"].endswith("19999\n20000\n")
    assert result["truncated"] is True
    assert len(result["stdout"]) < 2 * STREAM_EDGE + 100
    log = Path(result["log_path"]).read_text()
    assert "\n10000\n" in log and log.endswith("20000\n")


async def test_python_imports_from_the_workspace(
    workspace: Workspace, execs: Exec
) -> None:
    (workspace.root / "helper.py").write_text("VALUE = 42\n")
    result = await execs.run("python", "import helper; print(helper.VALUE)", 10)
    assert result["stdout"] == "42\n"


async def test_traceback_names_a_source_file_that_exists(execs: Exec) -> None:
    result = await execs.run("python", "raise SystemExit(undefined)", 10)
    assert result["exit_code"] == 1
    assert result["source_path"] in result["stderr"]
    assert Path(result["source_path"]).exists()


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
async def test_js_runs(execs: Exec) -> None:
    result = await execs.run("js", "console.log(6 * 7)", 10)
    assert result["stdout"] == "42\n"


async def test_timeout_kills_the_whole_process_group(
    workspace: Workspace, execs: Exec
) -> None:
    script = "sleep 60 & echo $! > bg.pid; echo started; sleep 60"
    with pytest.raises(ToolFailure) as caught:
        await execs.run("bash", script, 1)
    assert caught.value.code == TIMEOUT
    assert "started" in caught.value.data["stdout"]
    assert await wait_gone(int((workspace.root / "bg.pid").read_text()))


async def test_cancelling_the_call_kills_the_child(
    workspace: Workspace, execs: Exec
) -> None:
    task = asyncio.create_task(execs.run("bash", "echo $$ > me.pid; sleep 60", 60))
    pid_file = workspace.root / "me.pid"
    async with asyncio.timeout(10):
        while not pid_file.exists() or not pid_file.read_text():
            await asyncio.sleep(0.05)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert await wait_gone(int(pid_file.read_text()))
