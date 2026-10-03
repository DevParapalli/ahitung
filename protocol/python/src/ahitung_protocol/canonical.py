import hashlib
import json
import unicodedata
from typing import Any

# JavaScript's Number.MAX_SAFE_INTEGER. The TypeScript implementation cannot
# represent integers beyond it exactly, so neither side accepts them.
MAX_SAFE_INTEGER = 2**53 - 1


def canonical(value: Any) -> bytes:
    """RFC 8785 serialisation of a value restricted to ASCII keys and safe integers."""
    _check_profile(value)
    # Inside the profile, sorted keys, compact separators, and unescaped
    # non-ASCII produce exactly the JCS bytes: key order by code point equals
    # UTF-16 order for ASCII, and json escapes control characters as JCS does.
    text = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return text.encode("utf-8")


def tools_hash(tools: list[dict[str, Any]]) -> str:
    """Hash of a tool surface per protocol.md §9."""
    surface = [
        {
            "name": t["name"],
            "description": t["description"],
            "parameters": t["parameters"],
        }
        for t in tools
    ]
    surface.sort(key=lambda t: t["name"])
    return hashlib.sha256(canonical(_strip_whitespace(surface))).hexdigest()


def _check_profile(value: Any) -> None:
    match value:
        case None | bool() | str():
            pass
        case int():
            if abs(value) > MAX_SAFE_INTEGER:
                raise ValueError(f"integer outside the safe range: {value}")
        case list():
            for item in value:
                _check_profile(item)
        case dict():
            for key, item in value.items():
                if not isinstance(key, str) or not key.isascii():
                    raise ValueError(f"object key is not an ASCII string: {key!r}")
                _check_profile(item)
        case _:
            raise ValueError(
                f"type outside the canonical profile: {type(value).__name__}"
            )


def _is_whitespace(char: str) -> bool:
    return char in "\t\n\r " or unicodedata.category(char) == "Zs"


def _strip_whitespace(value: Any) -> Any:
    match value:
        case str():
            return "".join(c for c in value if not _is_whitespace(c))
        case list():
            return [_strip_whitespace(item) for item in value]
        case dict():
            stripped = {
                _strip_whitespace(k): _strip_whitespace(v) for k, v in value.items()
            }
            if len(stripped) != len(value):
                raise ValueError("stripping whitespace made two object keys equal")
            return stripped
        case _:
            return value
