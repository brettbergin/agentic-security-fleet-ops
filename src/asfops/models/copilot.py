"""GitHub Copilot SDK exposed as a pydantic-ai model provider.

The Copilot SDK is an agent runtime (it drives the Copilot CLI), not a raw
completion API. :class:`CopilotModel` flattens one runtime turn into one
pydantic-ai model response:

- the pydantic-ai system prompt + instructions replace the CLI's system
  message, so agents keep their own persona;
- the session runs tool-free with a reject-all permission handler, so the
  runtime behaves like a pure chat model;
- structured output uses pydantic-ai's *prompted* mode (schema injected into
  instructions and validated with retries), since the runtime cannot return
  tool calls to pydantic-ai;
- token usage is summed from the runtime's usage events.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncGenerator, AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from pydantic_ai.messages import (
    ModelMessage,
    ModelRequest,
    ModelResponse,
    ModelResponseStreamEvent,
    RetryPromptPart,
    SystemPromptPart,
    TextPart,
    UserPromptPart,
)
from pydantic_ai.models import Model, ModelRequestParameters, StreamedResponse
from pydantic_ai.profiles import ModelProfile
from pydantic_ai.settings import ModelSettings
from pydantic_ai.usage import RequestUsage

from asfops.exceptions import CopilotRuntimeError, ToolsNotSupportedError
from asfops.models.client import get_shared_client

if TYPE_CHECKING:
    from copilot import CopilotClient, PermissionRequest, PermissionRequestResult, SessionEvent
    from copilot.session import CopilotSession

DEFAULT_COPILOT_MODEL = "claude-sonnet-4.5"

COPILOT_PROFILE = ModelProfile(
    supports_tools=False,
    supports_json_schema_output=False,
    supports_json_object_output=False,
    default_structured_output_mode="prompted",
)


def _reject_all_permissions(
    request: PermissionRequest, context: dict[str, Any]
) -> PermissionRequestResult:
    from copilot.generated.rpc import PermissionDecisionReject

    return PermissionDecisionReject(
        feedback="This session is a pure chat model; tool execution is disabled."
    )


# eq=False keeps identity hashing — the SDK stores event handlers in a set.
@dataclass(eq=False)
class _TurnCollector:
    """Accumulates one Copilot turn from session events."""

    text_parts: list[str] = field(default_factory=list)
    usage: RequestUsage = field(default_factory=RequestUsage)
    model_name: str | None = None
    error: str | None = None
    done: asyncio.Event = field(default_factory=asyncio.Event)
    deltas: asyncio.Queue[object] | None = None

    def __call__(self, event: SessionEvent) -> None:
        from copilot.session_events import (
            AssistantMessageData,
            AssistantMessageDeltaData,
            AssistantUsageData,
            SessionErrorData,
            SessionIdleData,
        )

        data = event.data
        if isinstance(data, AssistantMessageData):
            # Only top-level assistant messages; sub-agent output would carry
            # a parent_tool_call_id (cannot happen in a tool-free session).
            if data.content and data.parent_tool_call_id is None:
                self.text_parts.append(data.content)
            if data.model:
                self.model_name = data.model
        elif isinstance(data, AssistantMessageDeltaData):
            if self.deltas is not None and data.delta_content:
                self.deltas.put_nowait(data.delta_content)
        elif isinstance(data, AssistantUsageData):
            details: dict[str, int] = {}
            if data.reasoning_tokens:
                details["reasoning_tokens"] = data.reasoning_tokens
            self.usage += RequestUsage(
                input_tokens=data.input_tokens or 0,
                output_tokens=data.output_tokens or 0,
                cache_read_tokens=data.cache_read_tokens or 0,
                cache_write_tokens=data.cache_write_tokens or 0,
                details=details,
            )
            if data.model:
                self.model_name = data.model
        elif isinstance(data, SessionErrorData):
            self.error = f"{data.error_type}: {data.message}"
            self._finish()
        elif isinstance(data, SessionIdleData):
            self._finish()

    def _finish(self) -> None:
        self.done.set()
        if self.deltas is not None:
            self.deltas.put_nowait(_STREAM_END)

    @property
    def text(self) -> str:
        return "\n\n".join(self.text_parts)


_STREAM_END = object()


def _map_messages(
    messages: list[ModelMessage],
    model_request_parameters: ModelRequestParameters,
) -> tuple[str, str]:
    """Flatten pydantic-ai message history into (system_text, prompt_text).

    pydantic-ai sends the full history on every request; the Copilot session is
    created fresh per request, so any prior exchanges are rendered into a
    transcript preamble ahead of the latest user message.
    """
    system_chunks: list[str] = []
    instruction_parts = Model._get_instruction_parts(messages, model_request_parameters)
    if instruction_parts:
        system_chunks.extend(p.content for p in instruction_parts)

    turns: list[tuple[str, str]] = []  # (role, text)
    for message in messages:
        if isinstance(message, ModelRequest):
            for part in message.parts:
                if isinstance(part, SystemPromptPart):
                    system_chunks.append(part.content)
                elif isinstance(part, UserPromptPart):
                    if not isinstance(part.content, str):
                        raise NotImplementedError(
                            "CopilotModel does not support non-text user content yet."
                        )
                    turns.append(("user", part.content))
                elif isinstance(part, RetryPromptPart):
                    turns.append(("user", part.model_response()))
                else:
                    raise NotImplementedError(
                        f"CopilotModel does not support message part {type(part).__name__}."
                    )
        elif isinstance(message, ModelResponse):
            text = "\n\n".join(p.content for p in message.parts if isinstance(p, TextPart))
            if text:
                turns.append(("assistant", text))

    if not turns:
        raise CopilotRuntimeError("No user prompt found in the request messages.")

    if len(turns) == 1:
        prompt = turns[0][1]
    else:
        transcript = "\n\n".join(f"[{role}]\n{text}" for role, text in turns[:-1])
        prompt = (
            "Below is the conversation so far, followed by the latest user message. "
            "Respond to the latest user message only.\n\n"
            f"{transcript}\n\n[user]\n{turns[-1][1]}"
        )
    return "\n\n".join(system_chunks), prompt


class CopilotModel(Model):
    """A pydantic-ai model that runs on the GitHub Copilot runtime.

    Usable anywhere a pydantic-ai model is accepted::

        from pydantic_ai import Agent
        from asfops import CopilotModel

        agent = Agent(model=CopilotModel("claude-sonnet-4.5"))

    Function tools are not supported (the Copilot runtime executes tools inside
    its own turn); use an API-key model for agents that need custom tools.
    """

    def __init__(
        self,
        model_name: str = DEFAULT_COPILOT_MODEL,
        *,
        client: CopilotClient | None = None,
        timeout: float = 600.0,
        system_message_mode: str = "replace",
        settings: ModelSettings | None = None,
        profile: ModelProfile | None = None,
    ) -> None:
        self._model_name = model_name
        self._client = client
        self._timeout = timeout
        self._system_message_mode = system_message_mode
        super().__init__(settings=settings, profile=profile or COPILOT_PROFILE)

    @property
    def model_name(self) -> str:
        return self._model_name

    @property
    def system(self) -> str:
        return "copilot"

    async def _get_client(self) -> CopilotClient:
        if self._client is not None:
            return self._client
        return await get_shared_client()

    def _check_unsupported(self, params: ModelRequestParameters) -> None:
        if params.function_tools or params.native_tools or params.output_mode == "tool":
            raise ToolsNotSupportedError(
                "CopilotModel does not support pydantic-ai function/native tools or "
                "tool-based structured output. Use prompted output (the default for "
                "this model) or switch to an API-key model for tool-using agents."
            )

    async def _open_session(
        self,
        client: CopilotClient,
        system_text: str,
        collector: _TurnCollector,
        *,
        streaming: bool,
    ) -> CopilotSession:
        system_message: Any = None
        if system_text:
            system_message = {"mode": self._system_message_mode, "content": system_text}
        try:
            return await client.create_session(
                model=self._model_name,
                system_message=system_message,
                available_tools=[],
                skip_custom_instructions=True,
                enable_config_discovery=False,
                on_permission_request=_reject_all_permissions,
                on_event=collector,
                streaming=streaming,
            )
        except Exception as exc:
            raise CopilotRuntimeError(
                f"Failed to create a Copilot session for model {self._model_name!r}."
            ) from exc

    async def _run_turn(
        self,
        client: CopilotClient,
        session: CopilotSession,
        prompt: str,
        collector: _TurnCollector,
    ) -> None:
        await session.send(prompt)
        try:
            await asyncio.wait_for(collector.done.wait(), timeout=self._timeout)
        except TimeoutError as exc:
            raise CopilotRuntimeError(
                f"Copilot turn timed out after {self._timeout:.0f}s (model {self._model_name!r})."
            ) from exc

    async def _close_session(self, client: CopilotClient, session: CopilotSession) -> None:
        try:
            await client.delete_session(session.session_id)
        except Exception:
            pass

    async def request(
        self,
        messages: list[ModelMessage],
        model_settings: ModelSettings | None,
        model_request_parameters: ModelRequestParameters,
    ) -> ModelResponse:
        model_settings, model_request_parameters = self.prepare_request(
            model_settings, model_request_parameters
        )
        self._check_unsupported(model_request_parameters)
        system_text, prompt = _map_messages(messages, model_request_parameters)

        client = await self._get_client()
        collector = _TurnCollector()
        session = await self._open_session(client, system_text, collector, streaming=False)
        try:
            await self._run_turn(client, session, prompt, collector)
        finally:
            await self._close_session(client, session)

        if collector.error is not None:
            raise CopilotRuntimeError(f"Copilot session error: {collector.error}")
        return ModelResponse(
            parts=[TextPart(content=collector.text)],
            usage=collector.usage,
            model_name=collector.model_name or self._model_name,
            timestamp=datetime.now(UTC),
            provider_name="copilot",
        )

    @asynccontextmanager
    async def request_stream(
        self,
        messages: list[ModelMessage],
        model_settings: ModelSettings | None,
        model_request_parameters: ModelRequestParameters,
        run_context: Any = None,
    ) -> AsyncGenerator[StreamedResponse]:
        model_settings, model_request_parameters = self.prepare_request(
            model_settings, model_request_parameters
        )
        self._check_unsupported(model_request_parameters)
        system_text, prompt = _map_messages(messages, model_request_parameters)

        client = await self._get_client()
        collector = _TurnCollector(deltas=asyncio.Queue())
        session = await self._open_session(client, system_text, collector, streaming=True)
        try:
            await session.send(prompt)
            yield CopilotStreamedResponse(
                model_request_parameters=model_request_parameters,
                _collector=collector,
                _model_name=self._model_name,
                _timeout=self._timeout,
            )
        finally:
            await self._close_session(client, session)


@dataclass
class CopilotStreamedResponse(StreamedResponse):
    """Streamed response backed by Copilot delta events."""

    _collector: _TurnCollector = None  # type: ignore[assignment]
    _model_name: str = ""
    _timeout: float = 600.0
    _timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))

    async def _get_event_iterator(self) -> AsyncIterator[ModelResponseStreamEvent]:
        queue = self._collector.deltas
        assert queue is not None
        while True:
            item = await asyncio.wait_for(queue.get(), timeout=self._timeout)
            if item is _STREAM_END:
                break
            assert isinstance(item, str)
            for event in self._parts_manager.handle_text_delta(
                vendor_part_id="content", content=item
            ):
                yield event
        self._usage = self._collector.usage
        if self._collector.error is not None:
            raise CopilotRuntimeError(f"Copilot session error: {self._collector.error}")

    @property
    def model_name(self) -> str:
        return self._collector.model_name or self._model_name

    @property
    def provider_name(self) -> str:
        return "copilot"

    @property
    def provider_url(self) -> str | None:
        return None

    @property
    def timestamp(self) -> datetime:
        return self._timestamp
