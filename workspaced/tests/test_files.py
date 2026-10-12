import hashlib

import pytest
from conftest import OTHER_SID, SID

from ahitung_workspaced.errors import (
    CHANGED_SINCE_READ,
    FILE_NOT_FOUND,
    PATCH_AMBIGUOUS,
    PATCH_INVALID_BYTES,
    PATCH_NO_MATCH,
    REFUSED,
    ToolFailure,
)
from ahitung_workspaced.files import INLINE_CAP_CHARS, Files
from ahitung_workspaced.paths import Workspace


@pytest.fixture
def files(workspace: Workspace) -> Files:
    return Files(workspace)


def _fail(fn, *args) -> ToolFailure:
    with pytest.raises(ToolFailure) as caught:
        fn(*args)
    return caught.value


def test_read_window_numbers_lines_and_hashes_whole_file(
    workspace: Workspace, files: Files
) -> None:
    data = b"".join(f"line {n}\n".encode() for n in range(1, 11))
    (workspace.root / "f.txt").write_bytes(data)
    result = files.read_file(SID, "f.txt", 3, 2)
    assert result["content"] == "     3\tline 3\n     4\tline 4\n"
    assert (result["start"], result["end"], result["total_lines"]) == (3, 4, 10)
    assert result["truncated"] is True
    assert result["sha256"] == hashlib.sha256(data).hexdigest()


def test_read_stops_at_the_character_cap_on_a_line_boundary(
    workspace: Workspace, files: Files
) -> None:
    (workspace.root / "f.txt").write_text("x" * 99 + "\n" * 1 + ("y" * 99 + "\n") * 200)
    result = files.read_file(SID, "f.txt", 1, 300)
    assert len(result["content"]) <= INLINE_CAP_CHARS
    assert result["content"].endswith("\n")
    assert result["end"] < 201 and result["truncated"] is True


def test_read_renders_and_flags_undecodable_bytes(
    workspace: Workspace, files: Files
) -> None:
    (workspace.root / "b.bin").write_bytes(b"ok\nbad \xff here\n")
    result = files.read_file(SID, "b.bin", 1, 300)
    assert "bad \\xff here" in result["content"]
    assert result["invalid_bytes"] is True


def test_missing_file_is_not_found(files: Files) -> None:
    assert _fail(files.read_file, SID, "nope.txt", 1, 300).code == FILE_NOT_FOUND


def test_edit_replaces_once_and_keeps_crlf(workspace: Workspace, files: Files) -> None:
    (workspace.root / "w.txt").write_bytes(b"a\r\nb\r\nc\r\n")
    files.read_file(SID, "w.txt", 1, 300)
    result = files.edit_file(SID, "w.txt", "b\r\n", "B\r\n")
    assert (workspace.root / "w.txt").read_bytes() == b"a\r\nB\r\nc\r\n"
    assert result["replaced_at_line"] == 2


def test_own_edit_refreshes_the_read_hash(workspace: Workspace, files: Files) -> None:
    (workspace.root / "f.txt").write_text("one\ntwo\n")
    files.read_file(SID, "f.txt", 1, 300)
    files.edit_file(SID, "f.txt", "one", "ONE")
    files.edit_file(SID, "f.txt", "two", "TWO")
    assert (workspace.root / "f.txt").read_text() == "ONE\nTWO\n"


def test_external_change_after_read_is_detected_per_session(
    workspace: Workspace, files: Files
) -> None:
    (workspace.root / "f.txt").write_text("one\n")
    files.read_file(SID, "f.txt", 1, 300)
    (workspace.root / "f.txt").write_text("one\nmore\n")
    assert _fail(files.edit_file, SID, "f.txt", "one", "1").code == CHANGED_SINCE_READ
    # A session that never read the file has no hash to compare against.
    files.edit_file(OTHER_SID, "f.txt", "one", "1")


def test_identical_rewrite_is_not_a_change(workspace: Workspace, files: Files) -> None:
    (workspace.root / "f.txt").write_text("one\n")
    files.read_file(SID, "f.txt", 1, 300)
    (workspace.root / "f.txt").write_text("one\n")
    files.edit_file(SID, "f.txt", "one", "1")


def test_no_match_points_at_the_closest_line(
    workspace: Workspace, files: Files
) -> None:
    (workspace.root / "f.py").write_text("def main():\n    return 1\n")
    failure = _fail(files.edit_file, SID, "f.py", "def mian():", "x")
    assert failure.code == PATCH_NO_MATCH
    assert "Closest line is 1" in failure.msg


def test_no_match_explains_crlf(workspace: Workspace, files: Files) -> None:
    (workspace.root / "f.txt").write_bytes(b"a\r\nb\r\n")
    failure = _fail(files.edit_file, SID, "f.txt", "a\nb", "x")
    assert failure.code == PATCH_NO_MATCH
    assert "CRLF" in failure.msg


def test_ambiguous_match_lists_lines(workspace: Workspace, files: Files) -> None:
    (workspace.root / "f.txt").write_text("x = 1\ny = 2\nx = 1\n")
    failure = _fail(files.edit_file, SID, "f.txt", "x = 1", "x = 3")
    assert failure.code == PATCH_AMBIGUOUS
    assert failure.data["lines"] == [1, 3]


def test_escaped_bytes_in_old_str_are_invalid_bytes(
    workspace: Workspace, files: Files
) -> None:
    (workspace.root / "b.bin").write_bytes(b"bad \xff here\n")
    failure = _fail(files.edit_file, SID, "b.bin", "bad \\xff here", "good")
    assert failure.code == PATCH_INVALID_BYTES


def test_line_number_prefixes_copied_from_a_read_are_stripped(
    workspace: Workspace, files: Files
) -> None:
    (workspace.root / "f.txt").write_text("alpha\nbeta\n")
    files.edit_file(SID, "f.txt", "     1\talpha\n     2\tbeta", "gamma")
    assert (workspace.root / "f.txt").read_text() == "gamma\n"


def test_tab_separated_content_is_not_mistaken_for_prefixes(
    workspace: Workspace, files: Files
) -> None:
    (workspace.root / "t.tsv").write_text("1\tone\n2\ttwo\n")
    files.edit_file(SID, "t.tsv", "1\tone", "1\tuno")
    assert (workspace.root / "t.tsv").read_text() == "1\tuno\n2\ttwo\n"


def test_write_refuses_existing_file_without_overwrite(
    workspace: Workspace, files: Files
) -> None:
    (workspace.root / "f.txt").write_text("keep")
    assert _fail(files.write_file, SID, "f.txt", "new", False).code == REFUSED
    assert (workspace.root / "f.txt").read_text() == "keep"


def test_write_creates_parents_byte_exact(workspace: Workspace, files: Files) -> None:
    result = files.write_file(SID, "a/b/c.txt", "no newline", False)
    assert (workspace.root / "a/b/c.txt").read_bytes() == b"no newline"
    assert result["created"] is True and result["bytes"] == 10


def test_overwrite_after_external_change_is_refused(
    workspace: Workspace, files: Files
) -> None:
    (workspace.root / "f.txt").write_text("v1")
    files.read_file(SID, "f.txt", 1, 300)
    (workspace.root / "f.txt").write_text("v2")
    assert _fail(files.write_file, SID, "f.txt", "v3", True).code == CHANGED_SINCE_READ


def test_overwrite_keeps_file_mode(workspace: Workspace, files: Files) -> None:
    target = workspace.root / "run.sh"
    target.write_text("echo 1\n")
    target.chmod(0o755)
    files.write_file(SID, "run.sh", "echo 2\n", True)
    assert target.stat().st_mode & 0o777 == 0o755


def test_insert_at_start_middle_and_end(workspace: Workspace, files: Files) -> None:
    (workspace.root / "f.txt").write_text("b\nd\n")
    files.insert_file(SID, "f.txt", 1, "a\n")
    files.insert_file(SID, "f.txt", 3, "c\n")
    files.insert_file(SID, "f.txt", 5, "e\n")
    assert (workspace.root / "f.txt").read_text() == "a\nb\nc\nd\ne\n"


def test_list_dir_hides_state_and_does_not_follow_links(
    workspace: Workspace, files: Files
) -> None:
    (workspace.root / "src").mkdir()
    (workspace.root / "src/main.py").write_text("")
    (workspace.root / "out").symlink_to("/etc")
    names = {e["name"]: e["type"] for e in files.list_dir(".", 3)["entries"]}
    assert names == {
        ".logs": "dir",
        "out": "symlink",
        "src": "dir",
        "src/main.py": "file",
    }
