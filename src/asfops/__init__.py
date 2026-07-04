"""asfops — Agentic Security Fleet Ops.

A security department of LLM agents: a Security Orchestrator triages any
assessment request, fans out to the relevant fleet members, and composes a
single comprehensive markdown report with optional usage metadata.

Quickstart::

    import asfops

    result = asfops.assess_sync("Review our new file-upload API design")
    print(result.report_md)
"""

try:
    # Written at build time by hatch-vcs (see pyproject [tool.hatch.build.hooks.vcs]).
    from asfops._version import __version__
except ImportError:  # running from a raw source tree that was never built
    try:
        from importlib.metadata import version as _pkg_version

        __version__ = _pkg_version("asfops")
    except Exception:  # pragma: no cover - not installed at all
        __version__ = "0.0.0"
from asfops.api import (
    Fleet,
    assess,
    assess_sync,
    compose_report,
    list_roles,
)
from asfops.config import FleetConfig
from asfops.exceptions import (
    AsfopsError,
    CopilotRuntimeError,
    RoleNotFoundError,
    ToolsNotSupportedError,
    TriageError,
)
from asfops.fleet.roles import REGISTRY, RoleRegistry, RoleSpec
from asfops.fleet.schemas import (
    AgentReport,
    Finding,
    RoleSelection,
    Severity,
    SynthesisSummary,
    TriageDecision,
)
from asfops.logs import (
    LoggingConfig,
    app_home,
    configure_logging,
    ensure_app_home,
    get_logger,
)
from asfops.models import CopilotBridge, CopilotModel, ModelRef, resolve_model, shutdown
from asfops.results import (
    AgentResult,
    AgentUsage,
    FleetEvent,
    FleetMetadata,
    FleetResult,
    ModelUsageTotals,
)

__all__ = [
    "REGISTRY",
    "AgentReport",
    "AgentResult",
    "AgentUsage",
    "AsfopsError",
    "CopilotBridge",
    "CopilotModel",
    "CopilotRuntimeError",
    "Finding",
    "Fleet",
    "FleetConfig",
    "FleetEvent",
    "FleetMetadata",
    "FleetResult",
    "LoggingConfig",
    "ModelRef",
    "ModelUsageTotals",
    "RoleNotFoundError",
    "RoleRegistry",
    "RoleSelection",
    "RoleSpec",
    "Severity",
    "SynthesisSummary",
    "ToolsNotSupportedError",
    "TriageDecision",
    "TriageError",
    "__version__",
    "app_home",
    "assess",
    "assess_sync",
    "compose_report",
    "configure_logging",
    "ensure_app_home",
    "get_logger",
    "list_roles",
    "resolve_model",
    "shutdown",
]
