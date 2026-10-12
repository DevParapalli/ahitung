from uuid import UUID

from fastmcp.server.dependencies import get_http_headers

from .errors import REFUSED, ToolFailure

# Carried as a header rather than in _meta because ADK's MCP client can set
# per-request headers but not _meta.
SESSION_HEADER = "x-ahit-session-id"


def session_id() -> str:
    """The calling chat session, from the request header."""
    raw = get_http_headers().get(SESSION_HEADER)
    if raw is None:
        raise ToolFailure(REFUSED, f"Missing the {SESSION_HEADER} request header.")
    # Any UUID version: ADK session IDs are not v7. Parsing also keeps the
    # value safe to use as a file name.
    try:
        return str(UUID(raw))
    except ValueError:
        raise ToolFailure(REFUSED, f"{SESSION_HEADER} is not a UUID.") from None
