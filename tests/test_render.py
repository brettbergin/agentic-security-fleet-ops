from __future__ import annotations

from datetime import UTC, datetime

from rich.console import Console

from asfops.cli.render import ProgressReporter, metadata_table, roster_table
from asfops.fleet.roles import REGISTRY
from asfops.fleet.schemas import RoleSelection, TriageDecision
from asfops.results import (
    AgentResult,
    AgentUsage,
    FleetEvent,
    FleetMetadata,
    FleetResult,
    aggregate_usage,
)


def _console() -> tuple[Console, list[str]]:
    lines: list[str] = []
    console = Console(file=None, record=True, force_terminal=False, width=100)
    return console, lines


def test_roster_table_lists_all_roles() -> None:
    table = roster_table(REGISTRY.all())
    console = Console(record=True, width=120)
    console.print(table)
    text = console.export_text()
    assert "appsec" in text
    assert "Threat Model Engineer" in text


def test_progress_reporter_renders_all_event_kinds() -> None:
    console = Console(record=True, width=100)
    reporter = ProgressReporter(console)
    for event in (
        FleetEvent(kind="triage_started"),
        FleetEvent(kind="triage_finished", detail="appsec, grc"),
        FleetEvent(kind="agent_started", slug="appsec"),
        FleetEvent(kind="agent_finished", slug="appsec"),
        FleetEvent(kind="agent_failed", slug="grc", detail="timeout"),
        FleetEvent(kind="synthesis_started"),
        FleetEvent(kind="synthesis_finished"),
    ):
        reporter(event)
    text = console.export_text()
    assert "Triaging" in text
    assert "appsec" in text
    assert "grc" in text
    assert "Synthesis complete" in text


def _result_with_metadata() -> FleetResult:
    usage = [
        AgentUsage(
            slug="appsec", model_id="test:test", input_tokens=100, output_tokens=50, requests=1
        ),
        AgentUsage(slug="grc", model_id="test:test", input_tokens=40, output_tokens=20, requests=1),
    ]
    totals, grand = aggregate_usage(usage)
    now = datetime.now(UTC)
    metadata = FleetMetadata(
        per_agent=usage,
        totals_by_model=totals,
        grand_total=grand,
        started_at=now,
        finished_at=now,
    )
    return FleetResult(
        request="r",
        triage=TriageDecision(
            selected=[RoleSelection(slug="appsec", rationale="x", priority="primary")],
            overall_rationale="o",
        ),
        agent_results=[
            AgentResult(
                role_slug="appsec",
                role_name="Application Security Engineer",
                model_id="test:test",
                usage=usage[0],
            )
        ],
        synthesis=None,
        report_md="# r",
        metadata=metadata,
    )


def test_metadata_table_present_and_none() -> None:
    result = _result_with_metadata()
    table = metadata_table(result)
    assert table is not None
    console = Console(record=True, width=100)
    console.print(table)
    assert "test:test" in console.export_text()

    result.metadata = None
    assert metadata_table(result) is None
