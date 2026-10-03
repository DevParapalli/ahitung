import json
from datetime import timedelta
from typing import Annotated, Any, ClassVar, Literal, Self, get_args

from pydantic import (
    UUID7,
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    NonNegativeInt,
    StringConstraints,
    model_validator,
)

PROTO = "ahitung/1"

# protocol.md §6.5: payloads above this size MUST be externalised as a ref.
INLINE_LIMIT_BYTES = 128 * 1024

# Any case on the wire; lowercased on parse so comparisons are case-blind.
Sha256 = Annotated[str, StringConstraints(pattern=r"^[0-9a-fA-F]{64}$", to_lower=True)]
Scope = Literal["session", "turn", "invocation", "block"]
TurnStop = Literal[
    "end_turn", "cancelled", "error", "max_invocations", "budget", "stalled"
]
InvocationStop = Literal["end_turn", "tool_use", "cancelled", "length", "error"]
AttachmentKind = Literal["image", "document", "audio", "video", "blob"]

# Which of (tid, inv, blk) each scope carries.
_SCOPE_FIELDS: dict[Scope, tuple[bool, bool, bool]] = {
    "session": (False, False, False),
    "turn": (True, False, False),
    "invocation": (True, True, False),
    "block": (True, True, True),
}


class Payload(BaseModel):
    model_config = ConfigDict(frozen=True, extra="ignore")

    @classmethod
    def of(cls, event: Payload) -> Self:
        """This payload's fields copied out of an event, leaving the envelope behind."""
        return cls(**{name: getattr(event, name) for name in cls.model_fields})


class Event(Payload):
    """Envelope shared by every event, protocol.md §3."""

    scope: ClassVar[Scope]
    producers: ClassVar[frozenset[str]]

    seq: int
    ts: AwareDatetime
    sid: UUID7
    tid: UUID7 | None = None
    inv: NonNegativeInt | None = None
    blk: NonNegativeInt | None = None
    src: str = Field(pattern=r"^(fe|be|worker|workspaced|(mcp|agent)\..+)$")
    t: str
    crit: Literal["info", "warn", "deny", "fatal"] = "info"

    @model_validator(mode="after")
    def _check_envelope(self) -> Self:
        if self.ts.utcoffset() != timedelta(0):
            raise ValueError("ts must be UTC")
        present = (self.tid is not None, self.inv is not None, self.blk is not None)
        if present != _SCOPE_FIELDS[self.scope]:
            raise ValueError(
                f"{self.t} is {self.scope}-scoped and carries the wrong tid/inv/blk"
            )
        if self.src.split(".")[0] not in self.producers:
            raise ValueError(f"{self.t} cannot be produced by {self.src}")
        # inv 0 is the user's contribution, so only the FE writes to it.
        if self.inv is not None and (self.src == "fe") != (self.inv == 0):
            raise ValueError("inv 0 is reserved for, and required of, src fe")
        return self


class Usage(Payload):
    in_: NonNegativeInt = Field(alias="in")
    out: NonNegativeInt
    cache_read: NonNegativeInt | None = None
    cache_write: NonNegativeInt | None = None
    reasoning: NonNegativeInt | None = None


class Attachment(Payload):
    kind: AttachmentKind
    mime: str
    name: str
    bytes: NonNegativeInt
    uri: str
    sha256: Sha256


class Ref(Payload):
    kind: AttachmentKind
    uri: str
    bytes: NonNegativeInt
    sha256: Sha256


class Window(Payload):
    start: NonNegativeInt
    stop: NonNegativeInt
    total: NonNegativeInt


class RejectedSetting(Payload):
    key: str
    code: str
    msg: str


class Settings(Payload):
    model: str | None = None
    provider: str | None = None
    params: dict[str, Any] | None = None
    continuation: dict[InvocationStop, Literal["continue", "end"]] | None = None
    approvals: list[str] | None = None
    advisory: bool | None = None


class Rejection(Payload):
    code: Literal[
        "sid.collision",
        "workspace.failed",
        "mcp.unreachable",
        "proto.unsupported",
        "resume.tools_changed",
    ]
    msg: str


class Ending(Payload):
    reason: Literal["client_closed", "shutdown", "error"]
    inferred: bool


class ResultOk(Payload):
    ms: NonNegativeInt
    content: str | None = None
    ref: Ref | None = None
    window: Window | None = None


class ResultError(Payload):
    code: str
    msg: str


class SessionRequest(Event):
    scope = "session"
    producers = frozenset({"fe"})
    t: Literal["session.request"]
    # One workspace serves every session; this only says whether to offer
    # its file and execution tools. False is a chat-only session.
    workspace: bool
    resume: UUID7 | None
    client: str


class SessionStart(Event):
    scope = "session"
    producers = frozenset({"be"})
    t: Literal["session.start"]
    proto: str
    workspace: bool
    tools_hash: Sha256


class SessionReject(Event, Rejection):
    scope = "session"
    producers = frozenset({"be"})
    t: Literal["session.reject"]


class SessionSettings(Event, Settings):
    scope = "session"
    producers = frozenset({"fe", "worker"})
    t: Literal["session.settings"]
    rejected: list[RejectedSetting] | None = None

    @model_validator(mode="after")
    def _check_snapshot(self) -> Self:
        if self.src == "worker" and (self.model is None or self.provider is None):
            raise ValueError("a worker snapshot carries model and provider")
        if self.src == "fe" and (
            self.rejected is not None or self.advisory is not None
        ):
            raise ValueError("rejected and advisory are worker-only")
        return self


class SessionEnd(Event, Ending):
    scope = "session"
    producers = frozenset({"be", "fe"})
    t: Literal["session.end"]


class TurnStart(Event):
    scope = "turn"
    producers = frozenset({"fe", "worker"})
    t: Literal["turn.start"]
    parent: UUID7 | None = None
    call_id: UUID7 | None = None
    agent: str | None = None

    @model_validator(mode="after")
    def _check_child(self) -> Self:
        child_fields = (self.parent, self.call_id, self.agent)
        expected_present = self.src == "worker"
        if any((f is not None) != expected_present for f in child_fields):
            raise ValueError(
                "parent, call_id, and agent are present exactly on worker turns"
            )
        return self


class TurnCancel(Event):
    scope = "turn"
    producers = frozenset({"fe"})
    t: Literal["turn.cancel"]
    reason: Literal["user_redirect", "user_stop"]
    next: UUID7 | None


class TurnEnd(Event):
    scope = "turn"
    producers = frozenset({"worker"})
    t: Literal["turn.end"]
    invocations: NonNegativeInt
    stop: TurnStop


class InvocationStart(Event):
    scope = "invocation"
    producers = frozenset({"worker"})
    t: Literal["invocation.start"]
    model: str
    provider: str | None = None


class InvocationEnd(Event):
    scope = "invocation"
    producers = frozenset({"worker"})
    t: Literal["invocation.end"]
    stop: InvocationStop
    usage: Usage


class MessageText(Event):
    scope = "block"
    producers = frozenset({"fe"})
    t: Literal["message.text"]
    text: str


class MessageAttachment(Event, Attachment):
    scope = "block"
    producers = frozenset({"fe", "worker"})
    t: Literal["message.attachment"]

    @model_validator(mode="after")
    def _check_uri(self) -> Self:
        scheme = "upload://" if self.src == "fe" else "payload://"
        if not self.uri.startswith(scheme):
            raise ValueError(f"an attachment from {self.src} uses {scheme}")
        return self


class Streamed(Event):
    """Base for the start/delta/end lifecycle of protocol.md §4."""

    scope = "block"
    producers = frozenset({"worker", "agent"})


class MessageTextStart(Streamed):
    t: Literal["message.text.start"]


class MessageTextDelta(Streamed):
    t: Literal["message.text.delta"]
    text: str


class MessageTextEnd(Streamed):
    t: Literal["message.text.end"]
    tokens: NonNegativeInt | None = None


class MessageReasoningStart(Streamed):
    t: Literal["message.reasoning.start"]


class MessageReasoningDelta(Streamed):
    t: Literal["message.reasoning.delta"]
    text: str


class MessageReasoningEnd(Streamed):
    t: Literal["message.reasoning.end"]
    tokens: NonNegativeInt | None = None


class ToolCall(Event):
    scope = "block"
    producers = frozenset({"worker", "agent"})
    t: Literal["tool.call"]
    call_id: UUID7
    name: str
    args: dict[str, Any]


class ToolExecStart(Event):
    scope = "turn"
    producers = frozenset({"workspaced", "mcp", "worker", "agent"})
    t: Literal["tool.exec.start"]
    call_id: UUID7


class ToolResultOk(Event, ResultOk):
    scope = "turn"
    producers = frozenset({"workspaced", "mcp", "worker", "agent"})
    t: Literal["tool.result.ok"]
    call_id: UUID7

    @model_validator(mode="after")
    def _check_body(self) -> Self:
        if (self.content is None) == (self.ref is None):
            raise ValueError("exactly one of content or ref is present")
        if self.content is not None and len(self.content.encode()) > INLINE_LIMIT_BYTES:
            raise ValueError("content above 128 KiB must be externalised as ref")
        return self


class ToolResultError(Event, ResultError):
    scope = "turn"
    producers = frozenset({"workspaced", "mcp", "worker", "agent"})
    t: Literal["tool.result.error"]
    call_id: UUID7


class ToolOutputDelta(Event):
    scope = "turn"
    producers = frozenset({"workspaced"})
    t: Literal["tool.output.delta"]
    call_id: UUID7
    text: str
    stream: Literal["stdout", "stderr"] | None = None


class ApprovalRequest(Event):
    scope = "turn"
    producers = frozenset({"worker"})
    t: Literal["approval.request"]
    approval_id: UUID7
    call_id: UUID7
    summary: str


class ApprovalGrant(Event):
    scope = "turn"
    producers = frozenset({"fe"})
    t: Literal["approval.grant"]
    approval_id: UUID7
    note: str | None = None


class ApprovalDeny(Event):
    scope = "turn"
    producers = frozenset({"fe"})
    t: Literal["approval.deny"]
    approval_id: UUID7
    note: str | None = None


EVENT_TYPES: dict[str, type[Event]] = {
    get_args(cls.model_fields["t"].annotation)[0]: cls
    for cls in (
        SessionRequest,
        SessionStart,
        SessionReject,
        SessionSettings,
        SessionEnd,
        TurnStart,
        TurnCancel,
        TurnEnd,
        InvocationStart,
        InvocationEnd,
        MessageText,
        MessageAttachment,
        MessageTextStart,
        MessageTextDelta,
        MessageTextEnd,
        MessageReasoningStart,
        MessageReasoningDelta,
        MessageReasoningEnd,
        ToolCall,
        ToolExecStart,
        ToolResultOk,
        ToolResultError,
        ToolOutputDelta,
        ApprovalRequest,
        ApprovalGrant,
        ApprovalDeny,
    )
}


def parse(line: str | bytes) -> Event | None:
    """One JSONL line as an event; None for a t this module does not know."""
    data = json.loads(line)
    if not isinstance(data, dict) or not isinstance(data.get("t"), str):
        raise ValueError("an event is a JSON object with a string t")
    model = EVENT_TYPES.get(data["t"])
    # protocol.md §2: unrecognised types are ignored, whatever their crit.
    return None if model is None else model.model_validate(data)
