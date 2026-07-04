"""Shared test fixtures and scripted-model helpers."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from typing import Any

from pydantic import BaseModel
from pydantic_ai.messages import ModelMessage, ModelResponse, TextPart, ToolCallPart
from pydantic_ai.models import ModelRequestParameters
from pydantic_ai.models.function import AgentInfo, FunctionModel
from pydantic_ai.models.test import TestModel
from pydantic_ai.settings import ModelSettings


def scripted_model(output: BaseModel, *, model_name: str = "scripted") -> FunctionModel:
    """A FunctionModel that always emits ``output``.

    Works whether the agent uses tool-based or prompted output: if an output
    tool is present it emits a matching ToolCallPart, otherwise it emits the
    JSON as text.
    """

    def fn(messages: list[ModelMessage], info: AgentInfo) -> ModelResponse:
        payload = output.model_dump(mode="json")
        if info.output_tools:
            tool = info.output_tools[0]
            return ModelResponse(
                parts=[ToolCallPart(tool_name=tool.name, args=payload)],
                model_name=model_name,
            )
        return ModelResponse(
            parts=[TextPart(content=output.model_dump_json())], model_name=model_name
        )

    return FunctionModel(fn, model_name=model_name)


def failing_model(message: str = "boom") -> FunctionModel:
    """A FunctionModel that raises when invoked."""

    def fn(messages: list[ModelMessage], info: AgentInfo) -> ModelResponse:
        raise RuntimeError(message)

    return FunctionModel(fn)


def dynamic_model(fn: Callable[[list[ModelMessage], AgentInfo], ModelResponse]) -> FunctionModel:
    return FunctionModel(fn)


class ConcurrencyTrackingModel(TestModel):
    """A TestModel that sleeps per request and records peak concurrency."""

    __test__ = False

    def __init__(self, tracker: ConcurrencyTracker, delay: float = 0.02) -> None:
        super().__init__()
        self._tracker = tracker
        self._delay = delay

    async def request(
        self,
        messages: list[ModelMessage],
        model_settings: ModelSettings | None,
        model_request_parameters: ModelRequestParameters,
    ) -> ModelResponse:
        async with self._tracker.enter():
            await asyncio.sleep(self._delay)
            return await super().request(messages, model_settings, model_request_parameters)


class ConcurrencyTracker:
    def __init__(self) -> None:
        self.active = 0
        self.peak = 0
        self._lock = asyncio.Lock()

    def enter(self) -> _TrackerScope:
        return _TrackerScope(self)


class _TrackerScope:
    def __init__(self, tracker: ConcurrencyTracker) -> None:
        self._tracker = tracker

    async def __aenter__(self) -> None:
        async with self._tracker._lock:
            self._tracker.active += 1
            self._tracker.peak = max(self._tracker.peak, self._tracker.active)

    async def __aexit__(self, *exc: object) -> None:
        async with self._tracker._lock:
            self._tracker.active -= 1


__all__ = [
    "Any",
    "ConcurrencyTracker",
    "ConcurrencyTrackingModel",
    "dynamic_model",
    "failing_model",
    "scripted_model",
]
