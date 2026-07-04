"""Fallback bridge: structured output over a Copilot session without pydantic-ai.

The primary path is :class:`~asfops.models.copilot.CopilotModel` inside a
pydantic-ai ``Agent``. If prompted output through the agentic runtime proves
unreliable in an environment, this bridge reimplements the same
schema-in-prompt / validate / retry loop directly against the SDK, so the
fleet keeps working with ``FleetConfig(copilot_mode="bridge")``.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

from pydantic import BaseModel, TypeAdapter, ValidationError
from pydantic_ai.usage import RequestUsage

from asfops.exceptions import CopilotRuntimeError
from asfops.models.client import get_shared_client
from asfops.models.copilot import DEFAULT_COPILOT_MODEL, CopilotModel, _TurnCollector

if TYPE_CHECKING:
    from copilot import CopilotClient

_JSON_INSTRUCTIONS = (
    "Respond with a single JSON object matching this JSON schema, and nothing "
    "else — no prose before or after, no markdown fence required:\n\n{schema}"
)

_FENCE_RE = re.compile(r"```(?:json)?\s*(.*?)```", re.DOTALL)


def extract_json(text: str) -> str:
    """Extract the JSON payload from a model reply.

    Tolerates markdown fences and surrounding prose; falls back to the first
    balanced ``{...}`` block.
    """
    text = text.strip()
    if match := _FENCE_RE.search(text):
        return match.group(1).strip()
    if text.startswith("{") and text.endswith("}"):
        return text
    start = text.find("{")
    if start == -1:
        raise ValueError("No JSON object found in the reply.")
    depth = 0
    in_string = False
    escaped = False
    for i, ch in enumerate(text[start:], start):
        if escaped:
            escaped = False
            continue
        if ch == "\\":
            escaped = in_string
            continue
        if ch == '"':
            in_string = not in_string
        elif not in_string:
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    return text[start : i + 1]
    raise ValueError("Unbalanced JSON object in the reply.")


@dataclass
class BridgeResult[OutputT: BaseModel]:
    output: OutputT
    usage: RequestUsage
    model_name: str


class CopilotBridge:
    """Structured single-turn calls against the Copilot runtime."""

    def __init__(
        self,
        model: str = DEFAULT_COPILOT_MODEL,
        *,
        client: CopilotClient | None = None,
        timeout: float = 600.0,
    ) -> None:
        self._model = CopilotModel(model, client=client, timeout=timeout)

    async def run_structured[OutputT: BaseModel](
        self,
        *,
        system_prompt: str,
        user_prompt: str,
        output_schema: type[OutputT],
        max_retries: int = 2,
    ) -> BridgeResult[OutputT]:
        adapter: TypeAdapter[OutputT] = TypeAdapter(output_schema)
        schema_json = json.dumps(adapter.json_schema(), indent=2)
        system_text = f"{system_prompt}\n\n{_JSON_INSTRUCTIONS.format(schema=schema_json)}"

        usage = RequestUsage()
        prompt = user_prompt
        last_error = ""
        model_name = self._model.model_name
        for _ in range(max_retries + 1):
            text, turn_usage, turn_model = await self._turn(system_text, prompt)
            usage += turn_usage
            model_name = turn_model or model_name
            try:
                output = adapter.validate_json(extract_json(text))
            except (ValueError, ValidationError) as exc:
                last_error = str(exc)
                prompt = (
                    f"{user_prompt}\n\nYour previous reply was not valid against the "
                    f"required JSON schema:\n{last_error}\n\nReply again with only a "
                    "single valid JSON object."
                )
                continue
            return BridgeResult(output=output, usage=usage, model_name=model_name)
        raise CopilotRuntimeError(
            f"Copilot bridge failed to produce valid {output_schema.__name__} output "
            f"after {max_retries + 1} attempts: {last_error}"
        )

    async def _turn(self, system_text: str, prompt: str) -> tuple[str, RequestUsage, str | None]:
        client = self._model._client or await get_shared_client()
        collector = _TurnCollector()
        session = await self._model._open_session(client, system_text, collector, streaming=False)
        try:
            await self._model._run_turn(client, session, prompt, collector)
        finally:
            await self._model._close_session(client, session)
        if collector.error is not None:
            raise CopilotRuntimeError(f"Copilot session error: {collector.error}")
        return collector.text, collector.usage, collector.model_name
