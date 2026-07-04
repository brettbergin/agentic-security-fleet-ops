"""Fleet: security-department roles, schemas, and agent construction."""

from asfops.fleet.member import build_agent
from asfops.fleet.roles import REGISTRY, RoleRegistry, RoleSpec
from asfops.fleet.roster import register_default_roles
from asfops.fleet.schemas import (
    SEVERITY_ORDER,
    AgentReport,
    Confidence,
    Finding,
    RoleSelection,
    Severity,
    SynthesisSummary,
    TriageDecision,
)

__all__ = [
    "REGISTRY",
    "SEVERITY_ORDER",
    "AgentReport",
    "Confidence",
    "Finding",
    "RoleRegistry",
    "RoleSelection",
    "RoleSpec",
    "Severity",
    "SynthesisSummary",
    "TriageDecision",
    "build_agent",
    "register_default_roles",
]
