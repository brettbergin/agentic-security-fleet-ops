"""Fakes for the github-copilot-sdk client/session, driven by scripted events.

The fake session replays a list of event payloads (the same dataclasses the
real SDK emits) through the ``on_event`` callback when ``send`` is called, so
CopilotModel can be tested without the Copilot CLI or a subscription.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any

from copilot.session_events import (
    AssistantMessageData,
    AssistantMessageDeltaData,
    AssistantUsageData,
    SessionIdleData,
)


@dataclass
class FakeEvent:
    """Stand-in for copilot.SessionEvent — CopilotModel only reads ``.data``."""

    data: Any


def message(content: str, *, model: str | None = None, parent: str | None = None) -> FakeEvent:
    return FakeEvent(
        AssistantMessageData(
            content=content, message_id="m1", model=model, parent_tool_call_id=parent
        )
    )


def delta(content: str) -> FakeEvent:
    return FakeEvent(AssistantMessageDeltaData(delta_content=content, message_id="m1"))


def usage(
    *,
    model: str = "claude-sonnet-4.5",
    input_tokens: int = 100,
    output_tokens: int = 50,
    cache_read: int = 0,
    cache_write: int = 0,
    reasoning: int = 0,
) -> FakeEvent:
    return FakeEvent(
        AssistantUsageData(
            model=model,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cache_read_tokens=cache_read,
            cache_write_tokens=cache_write,
            reasoning_tokens=reasoning,
        )
    )


def idle() -> FakeEvent:
    return FakeEvent(SessionIdleData(aborted=False))


@dataclass
class FakeSession:
    session_id: str
    on_event: Any
    events: list[FakeEvent]
    sent_prompts: list[str] = field(default_factory=list)

    async def send(self, prompt: str, **kwargs: Any) -> str:
        self.sent_prompts.append(prompt)

        async def replay() -> None:
            for event in self.events:
                self.on_event(event)

        asyncio.get_running_loop().create_task(replay())
        return "turn-1"


@dataclass
class FakeCopilotClient:
    """Replays scripted events; records every create_session call."""

    events: list[FakeEvent] = field(default_factory=list)
    create_session_calls: list[dict[str, Any]] = field(default_factory=list)
    sessions: list[FakeSession] = field(default_factory=list)
    deleted_session_ids: list[str] = field(default_factory=list)

    async def create_session(self, **kwargs: Any) -> FakeSession:
        self.create_session_calls.append(kwargs)
        session = FakeSession(
            session_id=f"s{len(self.sessions) + 1}",
            on_event=kwargs["on_event"],
            events=list(self.events),
        )
        self.sessions.append(session)
        return session

    async def delete_session(self, session_id: str) -> None:
        self.deleted_session_ids.append(session_id)
