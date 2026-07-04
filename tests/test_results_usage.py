from datetime import UTC, datetime

from asfops.fleet.schemas import (
    AgentReport,
    Finding,
    RoleSelection,
    Severity,
    SynthesisSummary,
    TriageDecision,
)
from asfops.results import (
    AgentResult,
    AgentUsage,
    FleetMetadata,
    aggregate_usage,
    build_report_md,
)


def usage(slug: str, model: str, inp: int, out: int, reqs: int = 1) -> AgentUsage:
    return AgentUsage(slug=slug, model_id=model, input_tokens=inp, output_tokens=out, requests=reqs)


def test_aggregate_groups_by_model() -> None:
    usages = [
        usage("appsec", "copilot:claude-sonnet-4.5", 100, 50),
        usage("threat-model", "copilot:claude-sonnet-4.5", 200, 60),
        usage("grc", "openai:gpt-5.2", 80, 40),
    ]
    totals, grand = aggregate_usage(usages)
    by_model = {t.model_id: t for t in totals}
    assert by_model["copilot:claude-sonnet-4.5"].input_tokens == 300
    assert by_model["copilot:claude-sonnet-4.5"].output_tokens == 110
    assert by_model["copilot:claude-sonnet-4.5"].requests == 2
    assert by_model["openai:gpt-5.2"].input_tokens == 80
    assert grand.input_tokens == 380
    assert grand.output_tokens == 150
    assert grand.requests == 3


def test_aggregate_empty() -> None:
    totals, grand = aggregate_usage([])
    assert totals == []
    assert grand.input_tokens == 0


def _sample_results() -> list[AgentResult]:
    return [
        AgentResult(
            role_slug="appsec",
            role_name="Application Security Engineer",
            model_id="test:test",
            report=AgentReport(
                summary="found sqli",
                findings=[
                    Finding(
                        title="SQL Injection",
                        severity=Severity.critical,
                        description="unparameterized query",
                        recommendation="use bind params",
                        references=["CWE-89"],
                    ),
                    Finding(
                        title="Verbose errors",
                        severity=Severity.low,
                        description="stack traces leak",
                        recommendation="hide traces",
                    ),
                ],
                confidence="high",
            ),
            usage=usage("appsec", "test:test", 100, 50),
        ),
        AgentResult(
            role_slug="grc",
            role_name="GRC & Compliance Engineer",
            model_id="test:test",
            error="TimeoutError: too slow",
            usage=AgentUsage(slug="grc", model_id="test:test"),
        ),
    ]


def _triage() -> TriageDecision:
    return TriageDecision(
        selected=[
            RoleSelection(slug="appsec", rationale="code review", priority="primary"),
            RoleSelection(slug="grc", rationale="controls", priority="supporting"),
        ],
        overall_rationale="mixed",
    )


def test_report_includes_findings_failures_and_severity_order() -> None:
    results = _sample_results()
    synthesis = SynthesisSummary(
        executive_summary="serious sqli risk",
        top_risks=["SQL injection"],
        recommended_next_steps=["parameterize queries"],
    )
    md = build_report_md("Review my API", _triage(), results, synthesis, None)
    assert "## Executive Summary" in md
    assert "serious sqli risk" in md
    # consolidated findings table: critical appears before low
    assert md.index("SQL Injection") < md.index("Verbose errors")
    # failed agent is surfaced, not hidden
    assert "Assessment failed: TimeoutError: too slow" in md
    assert "CWE-89" in md


def test_report_metadata_section_present_when_metadata_supplied() -> None:
    results = _sample_results()
    per_agent = [r.usage for r in results]
    totals, grand = aggregate_usage(per_agent)
    now = datetime.now(UTC)
    metadata = FleetMetadata(
        per_agent=per_agent,
        totals_by_model=totals,
        grand_total=grand,
        started_at=now,
        finished_at=now,
    )
    md = build_report_md("req", _triage(), results, None, metadata)
    assert "## Usage Metadata" in md
    assert "Totals by Model" in md


def test_report_no_metadata_section_when_none() -> None:
    md = build_report_md("req", _triage(), _sample_results(), None, None)
    assert "## Usage Metadata" not in md


def test_report_renders_synthesis_optional_branches() -> None:
    from asfops.results import build_agent_report_md

    synthesis = SynthesisSummary(
        executive_summary="exec",
        top_risks=["r1"],
        cross_cutting_themes=["theme1", "theme2"],
        recommended_next_steps=["step1"],
    )
    results = _sample_results()
    assert results[0].report is not None
    results[0].report.recommendations = ["rec1"]
    results[0].report.open_questions = ["q1"]
    md = build_report_md("req", _triage(), results, synthesis, None)
    assert "Cross-Cutting Themes" in md
    assert "theme1" in md
    assert "rec1" in md
    assert "q1" in md

    single = build_agent_report_md("Application Security Engineer", results[0].report)
    assert single.startswith("# Application Security Engineer")
    assert "SQL Injection" in single
    assert "Recommendations" in single
    assert "Open Questions" in single


def test_compose_report_builds_result() -> None:
    from asfops.api import compose_report

    results = _sample_results()
    result = compose_report("my request", _triage(), results, include_metadata=True)
    assert result.request == "my request"
    assert result.synthesis is None
    assert result.metadata is not None
    assert "SQL Injection" in result.report_md
    assert len(result.all_findings) == 2

    no_meta = compose_report("r", _triage(), results, include_metadata=False)
    assert no_meta.metadata is None


def test_usage_from_run_and_request() -> None:
    from pydantic_ai.usage import RequestUsage, RunUsage

    from asfops.results import usage_from_request, usage_from_run

    run = usage_from_run(
        "appsec", "test:test", RunUsage(input_tokens=10, output_tokens=5, requests=2), 1.5
    )
    assert run.input_tokens == 10
    assert run.requests == 2
    assert run.total_tokens == 15

    req = usage_from_request(
        "appsec", "test:test", RequestUsage(input_tokens=7, output_tokens=3), 0.5
    )
    assert req.requests == 1
    assert req.total_tokens == 10
