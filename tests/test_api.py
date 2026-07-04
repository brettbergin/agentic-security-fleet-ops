from __future__ import annotations

import asyncio

import pytest
from pydantic_ai.models.test import TestModel

import asfops
from asfops import Fleet, FleetConfig, FleetResult
from asfops.exceptions import RoleNotFoundError
from asfops.fleet.schemas import RoleSelection, SynthesisSummary, TriageDecision

from .conftest import scripted_model


def offline_config() -> FleetConfig:
    return FleetConfig(
        default_model=TestModel(),
        triage_model=scripted_model(
            TriageDecision(
                selected=[
                    RoleSelection(slug="appsec", rationale="code", priority="primary"),
                ],
                overall_rationale="scripted",
            )
        ),
        synthesis_model=scripted_model(
            SynthesisSummary(executive_summary="ok", top_risks=[], recommended_next_steps=[])
        ),
    )


async def test_fleet_assess_offline() -> None:
    result = await Fleet(offline_config()).assess("Review our API")
    assert isinstance(result, FleetResult)
    assert result.report_md.startswith("# Security Fleet Assessment")
    # fully serializable — the shape an LLM tool consumer would return
    assert '"request"' in result.model_dump_json()


async def test_run_role_offline() -> None:
    fleet = Fleet(FleetConfig(default_model=TestModel()))
    result = await fleet.run_role("threat-model", "model this")
    assert result.role_slug == "threat-model"
    assert result.report is not None


async def test_run_role_unknown_slug() -> None:
    fleet = Fleet(FleetConfig(default_model=TestModel()))
    with pytest.raises(RoleNotFoundError):
        await fleet.run_role("nope", "x")


def test_roster_and_list_roles() -> None:
    fleet = Fleet()
    assert len(fleet.roster()) == 17
    assert {r.slug for r in asfops.list_roles()} == {r.slug for r in fleet.roster()}


def test_assess_sync_rejects_running_loop() -> None:
    async def inner() -> None:
        with pytest.raises(RuntimeError, match="running event loop"):
            Fleet(offline_config()).assess_sync("x")

    asyncio.run(inner())


def test_assess_sync_offline() -> None:
    result = asfops.assess_sync("Review our API", config=offline_config())
    assert isinstance(result, FleetResult)
    assert result.synthesis is not None


def test_public_exports_present() -> None:
    for name in (
        "Fleet",
        "FleetConfig",
        "FleetResult",
        "CopilotModel",
        "assess",
        "assess_sync",
        "list_roles",
        "shutdown",
    ):
        assert hasattr(asfops, name), name
