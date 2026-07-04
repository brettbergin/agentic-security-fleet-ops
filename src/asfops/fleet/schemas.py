"""Shared structured-output schemas for fleet members and the orchestrator."""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, Field

Confidence = Literal["high", "medium", "low"]


class Severity(StrEnum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    informational = "informational"


SEVERITY_ORDER: dict[Severity, int] = {s: i for i, s in enumerate(Severity)}


class Finding(BaseModel):
    """A single security finding from a fleet member."""

    title: str = Field(description="Short, specific title for the finding.")
    severity: Severity
    description: str = Field(description="What the issue is and why it matters.")
    likelihood: str | None = Field(
        default=None, description="How likely exploitation/occurrence is, and why."
    )
    recommendation: str = Field(description="Concrete remediation or next step.")
    references: list[str] = Field(
        default_factory=list,
        description="Standards, CWEs, ATT&CK techniques, or docs that apply.",
    )


class AgentReport(BaseModel):
    """The uniform report every fleet member returns."""

    summary: str = Field(description="2-5 sentence summary of the assessment from this role.")
    findings: list[Finding] = Field(default_factory=list)
    recommendations: list[str] = Field(
        default_factory=list,
        description="Role-level recommendations beyond individual findings.",
    )
    open_questions: list[str] = Field(
        default_factory=list,
        description="Missing information that would change or sharpen this assessment.",
    )
    confidence: Confidence = Field(
        description="Confidence in this assessment given the information provided."
    )


class RoleSelection(BaseModel):
    """One role picked by triage."""

    slug: str = Field(description="Role slug, exactly as listed in the roster.")
    rationale: str = Field(description="Why this role is relevant to the request.")
    priority: Literal["primary", "supporting"] = Field(
        description="primary = core to the request; supporting = adds valuable perspective."
    )


class TriageDecision(BaseModel):
    """The orchestrator's routing decision."""

    selected: list[RoleSelection]
    overall_rationale: str = Field(
        description="One paragraph explaining the overall routing decision."
    )


class SynthesisSummary(BaseModel):
    """The synthesized executive view across all agent reports."""

    executive_summary: str = Field(
        description="3-6 sentence executive summary of the whole assessment."
    )
    top_risks: list[str] = Field(description="The most important risks, highest first.")
    cross_cutting_themes: list[str] = Field(
        default_factory=list,
        description="Themes multiple specialists independently raised.",
    )
    recommended_next_steps: list[str] = Field(
        description="Ordered, concrete next steps for the requester."
    )
