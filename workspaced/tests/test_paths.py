import pytest

from ahitung_workspaced.errors import INVALID_ARGS, REFUSED, ToolFailure
from ahitung_workspaced.paths import Workspace


def test_relative_and_absolute_resolve_to_the_same_file(workspace: Workspace) -> None:
    (workspace.root / "a.txt").write_text("x")
    assert workspace.resolve("a.txt") == workspace.resolve(
        str(workspace.root / "a.txt")
    )


def test_absolute_path_outside_is_refused(workspace: Workspace) -> None:
    with pytest.raises(ToolFailure) as caught:
        workspace.resolve("/etc/passwd")
    assert caught.value.code == REFUSED


def test_parent_component_is_refused(workspace: Workspace) -> None:
    (workspace.root / "sub").mkdir()
    with pytest.raises(ToolFailure) as caught:
        workspace.resolve("sub/../a.txt")
    assert caught.value.code == REFUSED


def test_symlink_planted_inside_pointing_out_is_refused(workspace: Workspace) -> None:
    (workspace.root / "escape").symlink_to("/etc")
    with pytest.raises(ToolFailure) as caught:
        workspace.resolve("escape/passwd")
    assert caught.value.code == REFUSED


def test_symlink_staying_inside_is_followed(workspace: Workspace) -> None:
    (workspace.root / "real.txt").write_text("x")
    (workspace.root / "link.txt").symlink_to("real.txt")
    assert workspace.resolve("link.txt") == workspace.root / "real.txt"


def test_state_dir_is_writable_by_nobody_but_workspaced(workspace: Workspace) -> None:
    (workspace.root / "sneaky").symlink_to(".workspaced")
    for raw in (".workspaced/reads/x.json", "sneaky/README.md"):
        with pytest.raises(ToolFailure) as caught:
            workspace.resolve(raw, write=True)
        assert caught.value.code == REFUSED


def test_empty_and_nul_paths_are_invalid(workspace: Workspace) -> None:
    for raw in ("", "a\0b"):
        with pytest.raises(ToolFailure) as caught:
            workspace.resolve(raw)
        assert caught.value.code == INVALID_ARGS


def test_prepare_writes_readme_and_gitignore(workspace: Workspace) -> None:
    assert (workspace.state / ".gitignore").read_text() == "*\n"
    assert "Do not edit" in (workspace.state / "README.md").read_text()
