"""Fleet configuration."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from asfops.logs import LoggingConfig
from asfops.models.resolve import ModelRef

CopilotMode = Literal["model", "bridge"]

DEFAULT_MODEL: ModelRef = "copilot:claude-sonnet-4.5"
DEFAULT_TRIAGE_FALLBACK: tuple[str, ...] = ("security-architect", "threat-model", "appsec")


@dataclass
class FleetConfig:
    """Configuration for a :class:`~asfops.api.Fleet` run.

    Any :class:`~asfops.models.resolve.ModelRef` is accepted for a model: a
    ``"copilot:<name>"`` string, a native pydantic-ai model string
    (``"openai:gpt-5.2"``, ``"anthropic:claude-sonnet-4-5"``, ``"test"``), or a
    ``Model`` instance.
    """

    default_model: ModelRef = DEFAULT_MODEL
    triage_model: ModelRef | None = None
    """Model used for triage; falls back to ``default_model``."""
    synthesis_model: ModelRef | None = None
    """Model used for synthesis; falls back to ``default_model``."""
    model_overrides: dict[str, ModelRef] = field(default_factory=dict)
    """Per-role-slug model overrides."""

    max_concurrency: int = 5
    per_agent_timeout_s: float = 300.0

    force_roles: tuple[str, ...] = ()
    """Roles always engaged, regardless of triage."""
    exclude_roles: tuple[str, ...] = ()
    """Roles never engaged, even if triage or force selects them."""

    include_metadata: bool = True
    copilot_mode: CopilotMode = "model"
    """Reserved: ``"bridge"`` routes Copilot agents through the manual bridge."""

    logging: LoggingConfig = field(default_factory=LoggingConfig)
    """Logging: a global structlog app log plus per-agent context logs."""

    on_empty_triage: Literal["fallback", "error"] = "fallback"
    """When triage selects nothing usable: engage a default core set, or raise."""

    def triage_model_ref(self) -> ModelRef:
        return self.triage_model if self.triage_model is not None else self.default_model

    def synthesis_model_ref(self) -> ModelRef:
        return self.synthesis_model if self.synthesis_model is not None else self.default_model

    def model_for_role(self, slug: str) -> ModelRef:
        return self.model_overrides.get(slug, self.default_model)
