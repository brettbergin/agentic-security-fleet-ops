from typing import Any, cast

import pytest
from pydantic import BaseModel
from pydantic_ai import Agent
from pydantic_ai.messages import (
    ModelMessage,
    ModelRequest,
    ModelResponse,
    SystemPromptPart,
    TextPart,
    UserPromptPart,
)
from pydantic_ai.models import ModelRequestParameters

from asfops.exceptions import CopilotRuntimeError, ToolsNotSupportedError
from asfops.models.copilot import CopilotModel, _map_messages

from .fakes.copilot_fakes import FakeCopilotClient, delta, idle, message, usage


def make_model(client: FakeCopilotClient, **kwargs: Any) -> CopilotModel:
    return CopilotModel("claude-sonnet-4.5", client=cast(Any, client), **kwargs)


def simple_request(prompt: str = "hello", system: str | None = None) -> list[ModelMessage]:
    parts: list[Any] = []
    if system is not None:
        parts.append(SystemPromptPart(content=system))
    parts.append(UserPromptPart(content=prompt))
    return [ModelRequest(parts=parts)]


async def test_request_returns_text_and_usage() -> None:
    client = FakeCopilotClient(
        events=[
            message("the answer"),
            usage(
                model="claude-sonnet-4.5-real", input_tokens=120, output_tokens=30, cache_read=10
            ),
            idle(),
        ]
    )
    model = make_model(client)
    response = await model.request(simple_request(), None, ModelRequestParameters())
    assert isinstance(response.parts[0], TextPart)
    assert response.parts[0].content == "the answer"
    assert response.usage.input_tokens == 120
    assert response.usage.output_tokens == 30
    assert response.usage.cache_read_tokens == 10
    assert response.model_name == "claude-sonnet-4.5-real"
    assert response.provider_name == "copilot"


async def test_usage_summed_across_multiple_events() -> None:
    client = FakeCopilotClient(
        events=[
            usage(input_tokens=100, output_tokens=10),
            message("part one"),
            usage(input_tokens=50, output_tokens=20, reasoning=5),
            idle(),
        ]
    )
    response = await make_model(client).request(simple_request(), None, ModelRequestParameters())
    assert response.usage.input_tokens == 150
    assert response.usage.output_tokens == 30
    assert response.usage.details.get("reasoning_tokens") == 5


async def test_system_prompt_maps_to_replace_system_message() -> None:
    client = FakeCopilotClient(events=[message("ok"), idle()])
    await make_model(client).request(
        simple_request(system="You are a security reviewer."),
        None,
        ModelRequestParameters(),
    )
    call = client.create_session_calls[0]
    assert call["system_message"]["mode"] == "replace"
    assert "security reviewer" in call["system_message"]["content"]
    assert call["available_tools"] == []
    assert call["skip_custom_instructions"] is True
    # session is cleaned up
    assert client.deleted_session_ids == ["s1"]


async def test_session_tool_free_and_permissions_rejected() -> None:
    client = FakeCopilotClient(events=[message("ok"), idle()])
    await make_model(client).request(simple_request(), None, ModelRequestParameters())
    handler = client.create_session_calls[0]["on_permission_request"]
    decision = handler(None, {})
    assert type(decision).__name__ == "PermissionDecisionReject"


async def test_function_tools_raise() -> None:
    from pydantic_ai.tools import ToolDefinition

    client = FakeCopilotClient(events=[message("ok"), idle()])
    params = ModelRequestParameters(
        function_tools=[ToolDefinition(name="t", parameters_json_schema={"type": "object"})]
    )
    with pytest.raises(ToolsNotSupportedError):
        await make_model(client).request(simple_request(), None, params)


async def test_history_flattened_into_transcript() -> None:
    messages: list[Any] = [
        ModelRequest(parts=[UserPromptPart(content="first question")]),
        ModelResponse(parts=[TextPart(content="first answer")]),
        ModelRequest(parts=[UserPromptPart(content="follow-up")]),
    ]
    _system_text, prompt = _map_messages(messages, ModelRequestParameters())
    assert "[user]\nfirst question" in prompt
    assert "[assistant]\nfirst answer" in prompt
    assert prompt.endswith("[user]\nfollow-up")


async def test_single_turn_prompt_not_framed() -> None:
    _, prompt = _map_messages(simple_request("just this"), ModelRequestParameters())
    assert prompt == "just this"


async def test_session_error_raises() -> None:
    from copilot.session_events import SessionErrorData

    from .fakes.copilot_fakes import FakeEvent

    client = FakeCopilotClient(
        events=[FakeEvent(SessionErrorData(error_type="quota", message="out of quota"))]
    )
    with pytest.raises(CopilotRuntimeError, match="out of quota"):
        await make_model(client).request(simple_request(), None, ModelRequestParameters())


async def test_timeout_raises() -> None:
    client = FakeCopilotClient(events=[message("never idles")])
    model = make_model(client, timeout=0.05)
    with pytest.raises(CopilotRuntimeError, match="timed out"):
        await model.request(simple_request(), None, ModelRequestParameters())


async def test_streaming_yields_deltas() -> None:
    client = FakeCopilotClient(
        events=[
            delta("Hello"),
            delta(", world"),
            message("Hello, world"),
            usage(input_tokens=10, output_tokens=3),
            idle(),
        ]
    )
    model = make_model(client)
    async with model.request_stream(simple_request(), None, ModelRequestParameters()) as stream:
        chunks: list[str] = []
        async for _event in stream:
            pass
        response = stream.get()
        chunks = [p.content for p in response.parts if isinstance(p, TextPart)]
    assert "".join(chunks) == "Hello, world"
    assert response.usage.output_tokens == 3


async def test_agent_end_to_end_with_prompted_output() -> None:
    class Verdict(BaseModel):
        risk: str
        score: int

    client = FakeCopilotClient(
        events=[
            message('{"risk": "high", "score": 8}'),
            usage(input_tokens=200, output_tokens=20),
            idle(),
        ]
    )
    agent: Agent[None, Verdict] = Agent(model=make_model(client), output_type=Verdict)
    result = await agent.run("Assess: SQL built by string concatenation")
    assert result.output == Verdict(risk="high", score=8)
    assert result.usage.input_tokens == 200
    # the prompted-output schema instructions must reach the session system message
    call = client.create_session_calls[0]
    assert "json" in call["system_message"]["content"].lower()


def test_model_id_and_profile() -> None:
    model = CopilotModel("gpt-5")
    assert model.model_name == "gpt-5"
    assert model.system == "copilot"
    profile = model.profile
    assert profile.get("supports_tools") is False
    assert profile.get("default_structured_output_mode") == "prompted"
