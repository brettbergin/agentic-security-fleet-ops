"""Fleet configuration."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Literal

from asfops.logs import LoggingConfig
from asfops.models.resolve import ModelRef

if TYPE_CHECKING:
    from pydantic_ai.settings import ModelSettings
    from pydantic_ai.usage import UsageLimits

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

    max_concurrency: int = 8
    """Max specialists run at once. 8 covers a typical 3-7 role selection in a
    single wave (no late-starting "tail" agent); raise toward the roster size for
    broad requests, or lower it if the Copilot runtime / rate limits push back."""
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

    # --- Model tuning & guards (applied to every agent run) ---
    temperature: float | None = None
    """Sampling temperature; lower is more deterministic. ``None`` uses the model default."""
    max_tokens: int | None = None
    """Max output tokens per agent response. ``None`` uses the model default."""
    per_agent_token_limit: int | None = None
    """Hard total-token cap per agent run; exceeding it fails that agent (via ``UsageLimits``)."""
    fallback_models: tuple[ModelRef, ...] = ()
    """Models tried in order if the primary raises a model/runtime error (via ``FallbackModel``)."""

    def triage_model_ref(self) -> ModelRef:
        return self.triage_model if self.triage_model is not None else self.default_model

    def synthesis_model_ref(self) -> ModelRef:
        return self.synthesis_model if self.synthesis_model is not None else self.default_model

    def model_for_role(self, slug: str) -> ModelRef:
        return self.model_overrides.get(slug, self.default_model)

    def model_settings(self) -> ModelSettings | None:
        """Build pydantic-ai ``ModelSettings`` from the tuning fields, or ``None``."""
        settings: dict[str, object] = {}
        if self.temperature is not None:
            settings["temperature"] = self.temperature
        if self.max_tokens is not None:
            settings["max_tokens"] = self.max_tokens
        return settings or None  # type: ignore[return-value]

    def usage_limits(self) -> UsageLimits | None:
        """Build a pydantic-ai ``UsageLimits`` from ``per_agent_token_limit``, or ``None``."""
        if self.per_agent_token_limit is None:
            return None
        from pydantic_ai.usage import UsageLimits

        return UsageLimits(total_tokens_limit=self.per_agent_token_limit)
