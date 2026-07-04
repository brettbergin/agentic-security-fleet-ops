"""Resolve user-facing model references into pydantic-ai Model instances."""

from __future__ import annotations

from pydantic_ai.models import Model, infer_model

from asfops.models.copilot import DEFAULT_COPILOT_MODEL, CopilotModel

ModelRef = str | Model
"""A model reference: ``"copilot:<name>"``, any pydantic-ai model string
(``"openai:gpt-5.2"``, ``"anthropic:claude-sonnet-4-5"``, ``"test"``), or a
:class:`pydantic_ai.models.Model` instance."""


def resolve_model(ref: ModelRef) -> Model:
    """Turn a model reference into a pydantic-ai ``Model`` instance."""
    if isinstance(ref, Model):
        return ref
    if ref == "copilot":
        return CopilotModel(DEFAULT_COPILOT_MODEL)
    if ref.startswith("copilot:"):
        return CopilotModel(ref.removeprefix("copilot:"))
    return infer_model(ref)
