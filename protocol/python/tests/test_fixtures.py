import json
from pathlib import Path

import pytest

from ahitung_protocol.events import parse
from ahitung_protocol.reducer import ProtocolError, State, reduce

FIXTURES = Path(__file__).parents[2] / "fixtures"


def _reduce_file(path: Path) -> State:
    state = State()
    for number, line in enumerate(path.read_text().splitlines(), start=1):
        try:
            event = parse(line)
            if event is not None:
                reduce(state, event)
        except (ProtocolError, ValueError) as error:
            error.add_note(f"line {number}")
            raise
    return state


def _cases() -> list[Path]:
    return sorted(FIXTURES.glob("*.jsonl"))


@pytest.mark.parametrize("path", _cases(), ids=lambda p: p.stem)
def test_fixture(path: Path) -> None:
    expected = json.loads(path.with_suffix(".expected.json").read_text())
    if "violation_at_line" in expected:
        with pytest.raises((ProtocolError, ValueError)) as caught:
            _reduce_file(path)
        assert caught.value.__notes__[-1] == f"line {expected['violation_at_line']}"
    else:
        state = _reduce_file(path)
        assert state.model_dump(mode="json", by_alias=True) == expected
