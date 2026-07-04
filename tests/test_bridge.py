from typing import Any, cast

import pytest
from pydantic import BaseModel

from asfops.exceptions import CopilotRuntimeError
from asfops.models.bridge import CopilotBridge, extract_json

from .fakes.copilot_fakes import FakeCopilotClient, idle, message, usage


class Verdict(BaseModel):
    risk: str
    score: int


def test_extract_json_bare() -> None:
    assert extract_json('{"a": 1}') == '{"a": 1}'


def test_extract_json_fenced() -> None:
    text = 'Here you go:\n```json\n{"a": 1}\n```\nHope that helps!'
    assert extract_json(text) == '{"a": 1}'


def test_extract_json_with_prose() -> None:
    text = 'Sure! The result is {"a": {"b": "}"}} as requested.'
    assert extract_json(text) == '{"a": {"b": "}"}}'


def test_extract_json_none() -> None:
    with pytest.raises(ValueError, match="No JSON object"):
        extract_json("no json here")


def make_bridge(client: FakeCopilotClient) -> CopilotBridge:
    return CopilotBridge("claude-sonnet-4.5", client=cast(Any, client))


async def test_run_structured_success() -> None:
    client = FakeCopilotClient(
        events=[
            message('```json\n{"risk": "low", "score": 2}\n```'),
            usage(input_tokens=80, output_tokens=15),
            idle(),
        ]
    )
    result = await make_bridge(client).run_structured(
        system_prompt="You are a risk scorer.",
        user_prompt="Score this",
        output_schema=Verdict,
    )
    assert result.output == Verdict(risk="low", score=2)
    assert result.usage.input_tokens == 80
    # schema instructions embedded in the session system message
    call = client.create_session_calls[0]
    assert "JSON schema" in call["system_message"]["content"]


async def test_run_structured_retries_then_fails() -> None:
    client = FakeCopilotClient(events=[message("not json at all"), idle()])
    with pytest.raises(CopilotRuntimeError, match="after 2 attempts"):
        await make_bridge(client).run_structured(
            system_prompt="sys",
            user_prompt="user",
            output_schema=Verdict,
            max_retries=1,
        )
    # one initial attempt + one retry, each on a fresh session
    assert len(client.create_session_calls) == 2
    retry_prompt = client.sessions[1].sent_prompts[0]
    assert "not valid" in retry_prompt
