import json
from pathlib import Path

import pytest

from ahitung_protocol.canonical import canonical, tools_hash

VECTORS = json.loads(
    (Path(__file__).parents[2] / "vectors" / "tools_hash.json").read_text()
)


@pytest.mark.parametrize("vector", VECTORS["valid"], ids=lambda v: v["name"])
def test_valid(vector: dict) -> None:
    assert tools_hash(vector["tools"]) == vector["hash"]


@pytest.mark.parametrize("vector", VECTORS["rejected"], ids=lambda v: v["name"])
def test_rejected(vector: dict) -> None:
    with pytest.raises(ValueError):
        tools_hash(vector["tools"])


def test_canonical_sorts_nested_keys_and_drops_whitespace() -> None:
    assert canonical({"b": [1, {"d": None, "c": True}], "a": "é"}) == (
        '{"a":"é","b":[1,{"c":true,"d":null}]}'.encode()
    )


def test_canonical_escapes_control_characters_as_jcs() -> None:
    assert canonical("\b\f\n\r\t\x0b\x7f") == b'"\\b\\f\\n\\r\\t\\u000b\x7f"'
