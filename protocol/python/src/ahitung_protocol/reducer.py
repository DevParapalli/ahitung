from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, Field

from .events import (
    PROTO,
    ApprovalDeny,
    ApprovalGrant,
    ApprovalRequest,
    Attachment,
    Ending,
    Event,
    InvocationEnd,
    InvocationStart,
    InvocationStop,
    MessageAttachment,
    MessageReasoningDelta,
    MessageReasoningEnd,
    MessageReasoningStart,
    MessageText,
    MessageTextDelta,
    MessageTextEnd,
    MessageTextStart,
    Rejection,
    ResultError,
    ResultOk,
    SessionEnd,
    SessionReject,
    SessionRequest,
    SessionSettings,
    SessionStart,
    Settings,
    ToolCall,
    ToolExecStart,
    ToolOutputDelta,
    ToolResultError,
    ToolResultOk,
    TurnCancel,
    TurnEnd,
    TurnStart,
    TurnStop,
    Usage,
)

MAX_INVOCATIONS = 48
MAX_DEPTH = 3


class ProtocolError(Exception):
    """An event that a conforming producer could not have emitted at this point."""


class Block(BaseModel):
    kind: Literal["text", "reasoning", "attachment", "tool_call"]
    text: str = ""
    closed: bool
    attachment: Attachment | None = None
    call_id: UUID | None = None


class Invocation(BaseModel):
    model: str | None = None
    provider: str | None = None
    stop: InvocationStop | None = None
    usage: Usage | None = None
    blocks: dict[int, Block] = Field(default_factory=dict)


class Turn(BaseModel):
    status: Literal["open", "draining", "ended"] = "open"
    committed: bool
    depth: int
    parent: UUID | None = None
    call_id: UUID | None = None
    agent: str | None = None
    next: UUID | None = None
    stop: TurnStop | None = None
    invocations: dict[int, Invocation] = Field(default_factory=dict)


class Call(BaseModel):
    tid: UUID
    inv: int
    name: str
    args: dict[str, Any]
    started: bool = False
    output: str = ""
    approval_id: UUID | None = None
    child: UUID | None = None
    result: ResultOk | ResultError | None = None


class Approval(BaseModel):
    call_id: UUID
    summary: str
    answer: Literal["granted", "denied"] | None = None
    note: str | None = None


class State(BaseModel):
    sid: UUID | None = None
    last_seq: int | None = None
    phase: Literal["new", "requested", "started", "rejected", "ended"] = "new"
    proto: str | None = None
    workspace: bool | None = None
    tools_hash: str | None = None
    rejection: Rejection | None = None
    ending: Ending | None = None
    settings: Settings | None = None
    turns: dict[UUID, Turn] = Field(default_factory=dict)
    calls: dict[UUID, Call] = Field(default_factory=dict)
    approvals: dict[UUID, Approval] = Field(default_factory=dict)


def reduce(state: State, event: Event) -> State:
    """Apply one event to state in place; raise ProtocolError if it is invalid."""
    _check_order(state, event)
    match event:
        case SessionRequest():
            _session_request(state, event)
        case SessionStart():
            _session_start(state, event)
        case SessionReject():
            _require(
                state.phase == "requested", "session.reject outside a pending request"
            )
            state.phase = "rejected"
            state.rejection = Rejection.of(event)
        case SessionSettings():
            _require(
                state.phase == "started", "session.settings outside a started session"
            )
            # A proposal from the FE never applies locally (§6.1); only snapshots count.
            if event.src == "worker":
                state.settings = Settings.of(event)
        case SessionEnd():
            _session_end(state, event)
        case TurnStart():
            _turn_start(state, event)
        case TurnCancel():
            _turn_cancel(state, event)
        case TurnEnd():
            _turn_end(state, event)
        case InvocationStart():
            _invocation_start(state, event)
        case InvocationEnd():
            invocation = _open_invocation(state, event)
            turn = _turn(state, event.tid)
            if turn.status == "draining":
                _require(
                    event.stop == "cancelled",
                    "a draining turn's invocation ends cancelled",
                )
            invocation.stop = event.stop
            invocation.usage = event.usage
        case MessageText() | MessageAttachment() if event.inv == 0:
            _user_input(state, event)
        case MessageAttachment():
            _add_block(
                state,
                event,
                Block(kind="attachment", closed=True, attachment=Attachment.of(event)),
            )
        case MessageTextStart():
            _add_block(state, event, Block(kind="text", closed=False))
        case MessageReasoningStart():
            _add_block(state, event, Block(kind="reasoning", closed=False))
        case MessageTextDelta():
            _streaming_block(state, event, "text").text += event.text
        case MessageReasoningDelta():
            _streaming_block(state, event, "reasoning").text += event.text
        case MessageTextEnd():
            _streaming_block(state, event, "text").closed = True
        case MessageReasoningEnd():
            _streaming_block(state, event, "reasoning").closed = True
        case ToolCall():
            _tool_call(state, event)
        case ToolExecStart():
            _tool_exec_start(state, event)
        case ToolOutputDelta():
            call = _pending_call(state, event.call_id, event.tid)
            _require(
                call.started,
                f"tool.output.delta before tool.exec.start for {event.call_id}",
            )
            call.output += event.text
        case ToolResultOk() | ToolResultError():
            _tool_result(state, event)
        case ApprovalRequest():
            _approval_request(state, event)
        case ApprovalGrant() | ApprovalDeny():
            _approval_answer(state, event)
    state.last_seq = event.seq
    return state


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ProtocolError(message)


def _check_order(state: State, event: Event) -> None:
    if state.phase == "new":
        _require(
            isinstance(event, SessionRequest), "a session opens with session.request"
        )
        return
    _require(
        event.sid == state.sid, f"event for session {event.sid} in session {state.sid}"
    )
    _require(
        event.seq > state.last_seq, f"seq {event.seq} does not follow {state.last_seq}"
    )


def _session_request(state: State, event: SessionRequest) -> None:
    state.sid = event.sid
    state.phase = "requested"


def _session_start(state: State, event: SessionStart) -> None:
    _require(state.phase == "requested", "session.start outside a pending request")
    _require(event.proto == PROTO, f"this reducer reads {PROTO}, not {event.proto}")
    state.phase = "started"
    state.proto = event.proto
    state.workspace = event.workspace
    state.tools_hash = event.tools_hash


def _session_end(state: State, event: SessionEnd) -> None:
    _require(state.phase == "started", "session.end outside a started session")
    state.phase = "ended"
    state.ending = Ending.of(event)
    # §6.1: ending a session cancels its open turn; the worker still drains it.
    for turn in state.turns.values():
        if turn.status == "open":
            turn.status = "draining"


def _turn(state: State, tid: UUID | None) -> Turn:
    turn = state.turns.get(tid)
    _require(turn is not None, f"unknown turn {tid}")
    return turn


def _turn_start(state: State, event: TurnStart) -> None:
    _require(state.phase == "started", "turn.start outside a started session")
    _require(event.tid not in state.turns, f"turn {event.tid} already exists")
    if event.src == "fe":
        holder = [
            t for t in state.turns.values() if t.parent is None and t.status == "open"
        ]
        _require(not holder, "turn.start while another turn holds the turn lock")
        state.turns[event.tid] = Turn(
            committed=False, depth=0, invocations={0: Invocation()}
        )
        return
    parent = _turn(state, event.parent)
    _require(parent.status == "open", f"child turn of non-open turn {event.parent}")
    call = _pending_call(state, event.call_id, event.parent)
    _require(call.child is None, f"call {event.call_id} already delegated")
    _require(parent.depth < MAX_DEPTH, f"delegation beyond depth {MAX_DEPTH}")
    call.child = event.tid
    state.turns[event.tid] = Turn(
        committed=True,
        depth=parent.depth + 1,
        parent=event.parent,
        call_id=event.call_id,
        agent=event.agent,
    )


def _turn_cancel(state: State, event: TurnCancel) -> None:
    turn = _turn(state, event.tid)
    _require(turn.parent is None, "the FE cancels only turns it opened")
    _require(turn.status == "open", f"turn.cancel on {turn.status} turn {event.tid}")
    turn.next = event.next
    _drain(state, event.tid)


def _drain(state: State, tid: UUID) -> None:
    state.turns[tid].status = "draining"
    # §7 step 4: children are cancelled by the same procedure.
    for child_tid, child in state.turns.items():
        if child.parent == tid and child.status == "open":
            _drain(state, child_tid)


def _turn_end(state: State, event: TurnEnd) -> None:
    turn = _turn(state, event.tid)
    _require(turn.status != "ended", f"turn {event.tid} already ended")
    if turn.status == "draining":
        _require(event.stop == "cancelled", "a draining turn ends cancelled")
    for number, invocation in turn.invocations.items():
        _require(
            number == 0 or invocation.stop is not None,
            f"turn.end with invocation {number} open",
        )
    for call_id, call in state.calls.items():
        _require(
            call.tid != event.tid or call.result is not None,
            f"turn.end with call {call_id} unresolved",
        )
    turn.status = "ended"
    turn.stop = event.stop


def _invocation_start(state: State, event: InvocationStart) -> None:
    turn = _turn(state, event.tid)
    _require(
        turn.status == "open", f"invocation.start on {turn.status} turn {event.tid}"
    )
    _require(turn.committed, "invocation.start before message.text commits the turn")
    _require(
        state.settings is not None,
        "invocation.start before the first settings snapshot",
    )
    _require(
        event.inv not in turn.invocations, f"invocation {event.inv} already exists"
    )
    _require(
        event.inv <= MAX_INVOCATIONS,
        f"invocation {event.inv} exceeds the cap of {MAX_INVOCATIONS}",
    )
    turn.invocations[event.inv] = Invocation(model=event.model, provider=event.provider)


def _open_invocation(state: State, event: Event) -> Invocation:
    invocation = _turn(state, event.tid).invocations.get(event.inv)
    _require(
        invocation is not None, f"unknown invocation {event.inv} in turn {event.tid}"
    )
    _require(invocation.stop is None, f"invocation {event.inv} already ended")
    return invocation


def _user_input(state: State, event: MessageText | MessageAttachment) -> None:
    turn = _turn(state, event.tid)
    _require(turn.parent is None, "a child turn has no inv 0")
    _require(not turn.committed, f"{event.t} after message.text committed the turn")
    if isinstance(event, MessageText):
        _add_block(state, event, Block(kind="text", text=event.text, closed=True))
        turn.committed = True
    else:
        _add_block(
            state,
            event,
            Block(kind="attachment", closed=True, attachment=Attachment.of(event)),
        )


def _add_block(state: State, event: Event, block: Block) -> None:
    invocation = _open_invocation(state, event)
    _require(event.blk not in invocation.blocks, f"block {event.blk} already exists")
    invocation.blocks[event.blk] = block


def _streaming_block(state: State, event: Event, kind: str) -> Block:
    block = _open_invocation(state, event).blocks.get(event.blk)
    _require(
        block is not None and block.kind == kind,
        f"{event.t} for block {event.blk}, which is not a {kind} block",
    )
    _require(not block.closed, f"{event.t} after block {event.blk} ended")
    return block


def _tool_call(state: State, event: ToolCall) -> None:
    _require(event.call_id not in state.calls, f"call {event.call_id} already exists")
    _add_block(
        state, event, Block(kind="tool_call", closed=True, call_id=event.call_id)
    )
    state.calls[event.call_id] = Call(
        tid=event.tid, inv=event.inv, name=event.name, args=event.args
    )


def _pending_call(state: State, call_id: UUID | None, tid: UUID | None) -> Call:
    call = state.calls.get(call_id)
    _require(call is not None, f"unknown call {call_id}")
    _require(call.tid == tid, f"call {call_id} belongs to turn {call.tid}, not {tid}")
    _require(call.result is None, f"call {call_id} already has a result")
    return call


def _tool_exec_start(state: State, event: ToolExecStart) -> None:
    call = _pending_call(state, event.call_id, event.tid)
    _require(not call.started, f"call {event.call_id} already started")
    # Gating is read at dispatch, not at tool.call: an approval added to the
    # settings mid-turn applies to calls that have not yet been dispatched.
    if _gated(state, call.name):
        _require(
            _granted(state, call), f"call {event.call_id} dispatched without approval"
        )
    call.started = True


def _gated(state: State, name: str) -> bool:
    return state.settings is not None and name in (state.settings.approvals or [])


def _granted(state: State, call: Call) -> bool:
    return (
        call.approval_id is not None
        and state.approvals[call.approval_id].answer == "granted"
    )


def _tool_result(state: State, event: ToolResultOk | ToolResultError) -> None:
    call = _pending_call(state, event.call_id, event.tid)
    if call.child is not None:
        _require(
            state.turns[call.child].status == "ended",
            "delegated result before the child turn ended",
        )
    if call.approval_id is not None:
        denied = isinstance(event, ToolResultError) and event.code == "tool.denied"
        _require(
            _granted(state, call) or denied,
            f"ungranted call {event.call_id} must end with tool.denied",
        )
    call.result = (
        ResultOk.of(event) if isinstance(event, ToolResultOk) else ResultError.of(event)
    )


def _approval_request(state: State, event: ApprovalRequest) -> None:
    _require(
        event.approval_id not in state.approvals,
        f"approval {event.approval_id} already exists",
    )
    call = _pending_call(state, event.call_id, event.tid)
    _require(
        _gated(state, call.name), f"approval requested for ungated tool {call.name}"
    )
    _require(call.approval_id is None, f"call {event.call_id} already has an approval")
    call.approval_id = event.approval_id
    state.approvals[event.approval_id] = Approval(
        call_id=event.call_id, summary=event.summary
    )


def _approval_answer(state: State, event: ApprovalGrant | ApprovalDeny) -> None:
    approval = state.approvals.get(event.approval_id)
    _require(approval is not None, f"unknown approval {event.approval_id}")
    _require(approval.answer is None, f"approval {event.approval_id} already answered")
    _require(
        state.calls[approval.call_id].tid == event.tid,
        f"approval {event.approval_id} is for another turn",
    )
    # An answer may race a cancellation that already resolved the call (§7 step
    # 5). It is recorded, but nothing acts on it: the call already has a result.
    approval.answer = "granted" if isinstance(event, ApprovalGrant) else "denied"
    approval.note = event.note
