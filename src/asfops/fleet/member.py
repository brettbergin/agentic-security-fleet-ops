"""Build a pydantic-ai agent for a fleet member."""

from __future__ import annotations

from pydantic_ai import Agent, ModelRetry
from pydantic_ai.models import Model

from asfops.fleet.roles import RoleSpec
from asfops.fleet.schemas import AgentReport, Severity

_ACTIONABLE = {Severity.critical, Severity.high}


def validate_report(report: AgentReport) -> AgentReport:
    """Semantic quality gate for a specialist's report.

    Raising :class:`~pydantic_ai.ModelRetry` asks the model to fix and resubmit
    (bounded by the agent's ``retries``) rather than accepting a weak report.
    """
    for finding in report.findings:
        if finding.severity in _ACTIONABLE and not finding.recommendation.strip():
            raise ModelRetry(
                f"Finding {finding.title!r} is {finding.severity.value} but has no "
                "recommendation. Every high/critical finding must include a concrete "
                "remediation."
            )
    if report.findings and not report.summary.strip():
        raise ModelRetry("The report lists findings but the summary is empty; add a brief summary.")
    return report


def build_agent(role: RoleSpec, model: Model, *, retries: int = 2) -> Agent[None, AgentReport]:
    """Create the agent that runs a single security-department role."""
    agent: Agent[None, AgentReport] = Agent(
        model=model,
        output_type=role.output_schema,
        system_prompt=role.system_prompt,
        retries=retries,
        name=role.slug,
    )
    agent.output_validator(validate_report)
    return agent
