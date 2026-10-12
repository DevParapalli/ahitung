import functools
import inspect
from collections.abc import Callable
from typing import Any

from fastmcp.tools.base import ToolResult
from mcp.types import TextContent

# protocol.md §6.5 codes this server produces.
REFUSED = "tool.refused"
INVALID_ARGS = "tool.invalid_args"
TIMEOUT = "tool.timeout"
FILE_NOT_FOUND = "file.not_found"
CHANGED_SINCE_READ = "file.changed_since_read"
PATCH_NO_MATCH = "patch.no_match"
PATCH_AMBIGUOUS = "patch.ambiguous"
PATCH_INVALID_BYTES = "patch.invalid_bytes"
HANDLE_EXISTS = "handle.exists"
HANDLE_NOT_FOUND = "handle.not_found"
HANDLE_EVICTED = "handle.evicted"


class ToolFailure(Exception):
    """A failure the model can correct, returned as isError rather than raised."""

    def __init__(self, code: str, msg: str, **data: Any) -> None:
        super().__init__(msg)
        self.code = code
        self.msg = msg
        self.data = data


def as_result(failure: ToolFailure) -> ToolResult:
    """The isError result; the worker classifies on `code`, never on text."""
    return ToolResult(
        content=[TextContent(type="text", text=failure.msg)],
        structured_content={"code": failure.code, "msg": failure.msg, **failure.data},
        is_error=True,
    )


def tool_errors[F: Callable[..., Any]](fn: F) -> F:
    """Return a ToolFailure raised by the tool as its isError result."""
    if inspect.iscoroutinefunction(fn):

        @functools.wraps(fn)
        async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
            try:
                return await fn(*args, **kwargs)
            except ToolFailure as failure:
                return as_result(failure)

        return async_wrapper  # type: ignore[return-value]

    @functools.wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        try:
            return fn(*args, **kwargs)
        except ToolFailure as failure:
            return as_result(failure)

    return wrapper  # type: ignore[return-value]
