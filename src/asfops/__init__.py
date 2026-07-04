"""asfops — Agentic Security Fleet Ops.

A security department of LLM agents: a Security Orchestrator triages any
assessment request, fans out to the relevant fleet members, and composes a
single comprehensive markdown report with optional usage metadata.

Quickstart::

    import asfops

    result = asfops.assess_sync("Review our new file-upload API design")
    print(result.report_md)
"""

from asfops._version import __version__
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
from asfops.logs import LoggingConfig, configure_logging, get_logger
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
    "assess",
    "assess_sync",
    "compose_report",
    "configure_logging",
    "get_logger",
    "list_roles",
    "resolve_model",
    "shutdown",
]
