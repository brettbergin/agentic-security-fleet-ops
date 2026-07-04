"""Result models, usage aggregation, and markdown report assembly."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field
from pydantic_ai.usage import RequestUsage, RunUsage

from asfops.fleet.roles import REGISTRY
from asfops.fleet.schemas import (
    SEVERITY_ORDER,
    AgentReport,
    Finding,
    Severity,
    SynthesisSummary,
    TriageDecision,
)

FleetEventKind = Literal[
    "triage_started",
    "triage_finished",
    "agent_started",
    "agent_finished",
    "agent_failed",
    "synthesis_started",
    "synthesis_finished",
]


class FleetEvent(BaseModel):
    """Progress event emitted during a run (drives the CLI progress display)."""

    kind: FleetEventKind
    slug: str | None = None
    detail: str | None = None


class AgentUsage(BaseModel):
    """Usage for one agent invocation."""

    slug: str
    model_id: str
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0
    requests: int = 0
    duration_s: float = 0.0

    @property
    def total_tokens(self) -> int:
        return self.input_tokens + self.output_tokens


class ModelUsageTotals(BaseModel):
    """Aggregated usage for one model across the run."""

    model_id: str
    requests: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0

    @property
    def total_tokens(self) -> int:
        return self.input_tokens + self.output_tokens


class AgentResult(BaseModel):
    """The outcome of engaging one fleet member."""

    role_slug: str
    role_name: str
    model_id: str
    report: AgentReport | None = None
    error: str | None = None
    duration_s: float = 0.0
    usage: AgentUsage

    @property
    def ok(self) -> bool:
        return self.report is not None


class FleetMetadata(BaseModel):
    """Model + token-usage metadata for the whole assessment."""

    per_agent: list[AgentUsage] = Field(default_factory=list)
    totals_by_model: list[ModelUsageTotals] = Field(default_factory=list)
    grand_total: ModelUsageTotals
    started_at: datetime
    finished_at: datetime

    @property
    def duration_s(self) -> float:
        return (self.finished_at - self.started_at).total_seconds()


class FleetResult(BaseModel):
    """The complete result of a fleet assessment."""

    request: str
    triage: TriageDecision
    agent_results: list[AgentResult]
    synthesis: SynthesisSummary | None
    report_md: str
    metadata: FleetMetadata | None = None

    @property
    def all_findings(self) -> list[Finding]:
        findings: list[Finding] = []
        for result in self.agent_results:
            if result.report is not None:
                findings.extend(result.report.findings)
        return findings


def usage_from_run(slug: str, model_id: str, usage: RunUsage, duration_s: float) -> AgentUsage:
    """Convert a pydantic-ai ``RunUsage`` into an :class:`AgentUsage`."""
    return AgentUsage(
        slug=slug,
        model_id=model_id,
        input_tokens=usage.input_tokens or 0,
        output_tokens=usage.output_tokens or 0,
        cache_read_tokens=usage.cache_read_tokens or 0,
        cache_write_tokens=usage.cache_write_tokens or 0,
        requests=usage.requests or 0,
        duration_s=duration_s,
    )


def usage_from_request(
    slug: str, model_id: str, usage: RequestUsage, duration_s: float
) -> AgentUsage:
    """Convert a single-request ``RequestUsage`` (bridge path) into ``AgentUsage``."""
    return AgentUsage(
        slug=slug,
        model_id=model_id,
        input_tokens=usage.input_tokens or 0,
        output_tokens=usage.output_tokens or 0,
        cache_read_tokens=usage.cache_read_tokens or 0,
        cache_write_tokens=usage.cache_write_tokens or 0,
        requests=1,
        duration_s=duration_s,
    )


def aggregate_usage(usages: list[AgentUsage]) -> tuple[list[ModelUsageTotals], ModelUsageTotals]:
    """Group per-agent usage by model, returning (per-model totals, grand total)."""
    by_model: dict[str, ModelUsageTotals] = {}
    grand = ModelUsageTotals(model_id="all")
    for u in usages:
        totals = by_model.setdefault(u.model_id, ModelUsageTotals(model_id=u.model_id))
        for target in (totals, grand):
            target.requests += u.requests
            target.input_tokens += u.input_tokens
            target.output_tokens += u.output_tokens
            target.cache_read_tokens += u.cache_read_tokens
            target.cache_write_tokens += u.cache_write_tokens
    ordered = sorted(by_model.values(), key=lambda t: t.model_id)
    return ordered, grand


def _severity_key(finding: Finding) -> int:
    return SEVERITY_ORDER[finding.severity]


def build_report_md(
    request: str,
    triage: TriageDecision,
    agent_results: list[AgentResult],
    synthesis: SynthesisSummary | None,
    metadata: FleetMetadata | None,
) -> str:
    """Assemble the comprehensive markdown report deterministically."""
    lines: list[str] = ["# Security Fleet Assessment", ""]

    lines += ["## Request", "", "> " + request.strip().replace("\n", "\n> "), ""]

    if synthesis is not None:
        lines += ["## Executive Summary", "", synthesis.executive_summary, ""]
        if synthesis.top_risks:
            lines += ["### Top Risks", ""]
            lines += [f"{i}. {r}" for i, r in enumerate(synthesis.top_risks, 1)]
            lines.append("")
        if synthesis.cross_cutting_themes:
            lines += ["### Cross-Cutting Themes", ""]
            lines += [f"- {t}" for t in synthesis.cross_cutting_themes]
            lines.append("")
        if synthesis.recommended_next_steps:
            lines += ["### Recommended Next Steps", ""]
            lines += [f"{i}. {s}" for i, s in enumerate(synthesis.recommended_next_steps, 1)]
            lines.append("")

    lines += ["## Specialists Engaged", ""]
    lines += ["| Role | Priority | Rationale |", "| --- | --- | --- |"]
    priority_by_slug = {sel.slug: sel for sel in triage.selected}
    for result in agent_results:
        sel = priority_by_slug.get(result.role_slug)
        priority = sel.priority if sel else "—"
        rationale = (sel.rationale if sel else "").replace("|", "\\|")
        lines.append(f"| {result.role_name} | {priority} | {rationale} |")
    lines.append("")

    consolidated = _consolidated_findings(agent_results)
    if consolidated:
        lines += ["## Consolidated Findings", ""]
        lines += ["| Severity | Finding | Role |", "| --- | --- | --- |"]
        for _slug, name, finding in consolidated:
            title = finding.title.replace("|", "\\|")
            lines.append(f"| {finding.severity.value} | {title} | {name} |")
        lines.append("")

    lines += ["## Specialist Reports", ""]
    for result in agent_results:
        lines += [f"### {result.role_name}", ""]
        if result.report is None:
            lines += [f"_Assessment failed: {result.error}_", ""]
            continue
        report = result.report
        lines += [report.summary, "", f"**Confidence:** {report.confidence}", ""]
        for finding in sorted(report.findings, key=_severity_key):
            lines += [f"#### [{finding.severity.value.upper()}] {finding.title}", ""]
            lines += [finding.description, ""]
            if finding.likelihood:
                lines += [f"**Likelihood:** {finding.likelihood}", ""]
            lines += [f"**Recommendation:** {finding.recommendation}", ""]
            if finding.references:
                lines += ["**References:** " + ", ".join(finding.references), ""]
        if report.recommendations:
            lines += ["**Recommendations:**", ""]
            lines += [f"- {r}" for r in report.recommendations]
            lines.append("")
        if report.open_questions:
            lines += ["**Open Questions:**", ""]
            lines += [f"- {q}" for q in report.open_questions]
            lines.append("")

    if metadata is not None:
        lines += _metadata_section(metadata)

    return "\n".join(lines).rstrip() + "\n"


def build_agent_report_md(role_name: str, report: AgentReport) -> str:
    """Render a single agent's report as standalone markdown."""
    lines: list[str] = [f"# {role_name}", "", report.summary, ""]
    lines += [f"**Confidence:** {report.confidence}", ""]
    for finding in sorted(report.findings, key=_severity_key):
        lines += [f"## [{finding.severity.value.upper()}] {finding.title}", ""]
        lines += [finding.description, ""]
        if finding.likelihood:
            lines += [f"**Likelihood:** {finding.likelihood}", ""]
        lines += [f"**Recommendation:** {finding.recommendation}", ""]
        if finding.references:
            lines += ["**References:** " + ", ".join(finding.references), ""]
    if report.recommendations:
        lines += ["## Recommendations", ""]
        lines += [f"- {r}" for r in report.recommendations]
        lines.append("")
    if report.open_questions:
        lines += ["## Open Questions", ""]
        lines += [f"- {q}" for q in report.open_questions]
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def _consolidated_findings(
    agent_results: list[AgentResult],
) -> list[tuple[str, str, Finding]]:
    rows: list[tuple[str, str, Finding]] = []
    for result in agent_results:
        if result.report is None:
            continue
        for finding in result.report.findings:
            rows.append((result.role_slug, result.role_name, finding))
    rows.sort(key=lambda row: _severity_key(row[2]))
    return rows


def _metadata_section(metadata: FleetMetadata) -> list[str]:
    lines = ["## Usage Metadata", ""]
    lines += ["### Per Agent", ""]
    lines += [
        "| Role | Model | Requests | Input | Output | Duration (s) |",
        "| --- | --- | ---: | ---: | ---: | ---: |",
    ]
    for u in metadata.per_agent:
        lines.append(
            f"| {u.slug} | {u.model_id} | {u.requests} | {u.input_tokens} | "
            f"{u.output_tokens} | {u.duration_s:.1f} |"
        )
    lines.append("")
    lines += ["### Totals by Model", ""]
    lines += [
        "| Model | Requests | Input | Output | Cache Read | Cache Write |",
        "| --- | ---: | ---: | ---: | ---: | ---: |",
    ]
    for t in metadata.totals_by_model:
        lines.append(
            f"| {t.model_id} | {t.requests} | {t.input_tokens} | {t.output_tokens} | "
            f"{t.cache_read_tokens} | {t.cache_write_tokens} |"
        )
    g = metadata.grand_total
    lines.append(
        f"| **all** | **{g.requests}** | **{g.input_tokens}** | **{g.output_tokens}** | "
        f"**{g.cache_read_tokens}** | **{g.cache_write_tokens}** |"
    )
    lines.append("")
    return lines


__all__ = [
    "REGISTRY",
    "AgentResult",
    "AgentUsage",
    "FleetEvent",
    "FleetMetadata",
    "FleetResult",
    "ModelUsageTotals",
    "Severity",
    "aggregate_usage",
    "build_agent_report_md",
    "build_report_md",
    "usage_from_request",
    "usage_from_run",
]
