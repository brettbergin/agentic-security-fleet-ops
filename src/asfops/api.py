"""The public asfops API: the Fleet and module-level conveniences.

Designed as the interface an LLM tool-caller would want: one free-text
entrypoint (:meth:`Fleet.assess`), a discoverable roster
(:func:`list_roles`), a targeted single-expert call (:meth:`Fleet.run_role`),
and a fully ``model_dump_json()``-able :class:`~asfops.results.FleetResult`.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime

from asfops.config import FleetConfig
from asfops.fleet.roles import REGISTRY, RoleRegistry, RoleSpec
from asfops.fleet.schemas import RoleSelection, TriageDecision
from asfops.models.client import shutdown
from asfops.orchestrator import EventCallback, Orchestrator
from asfops.results import (
    AgentResult,
    FleetMetadata,
    FleetResult,
    aggregate_usage,
    build_report_md,
)


class Fleet:
    """The security fleet: triage, invoke specialists, synthesize a report."""

    def __init__(
        self, config: FleetConfig | None = None, *, registry: RoleRegistry | None = None
    ) -> None:
        self.config = config or FleetConfig()
        self.registry = registry or REGISTRY
        self._orchestrator = Orchestrator(self.config, registry=self.registry)

    async def assess(self, request: str, *, on_event: EventCallback | None = None) -> FleetResult:
        """Run a full assessment: triage → fan-out → synthesis → report."""
        return await self._orchestrator.run(request, on_event=on_event)

    def assess_sync(self, request: str, *, on_event: EventCallback | None = None) -> FleetResult:
        """Synchronous wrapper around :meth:`assess`.

        Raises if called from within a running event loop (e.g. Jupyter);
        ``await fleet.assess(...)`` there instead.
        """
        _guard_no_running_loop()
        return asyncio.run(self.assess(request, on_event=on_event))

    async def run_role(self, slug: str, request: str) -> AgentResult:
        """Engage a single specialist by slug (no triage, no synthesis)."""
        self.registry.get(slug)  # validates slug, raises RoleNotFoundError
        sel = RoleSelection(slug=slug, rationale="Directly requested.", priority="primary")
        return await self._orchestrator._run_role(sel, request, on_event=None)

    def run_role_sync(self, slug: str, request: str) -> AgentResult:
        _guard_no_running_loop()
        return asyncio.run(self.run_role(slug, request))

    def roster(self) -> tuple[RoleSpec, ...]:
        """The specialists available to this fleet."""
        return self.registry.all()

    async def aclose(self) -> None:
        """Shut down the shared Copilot runtime, if one was started."""
        await shutdown()


def _guard_no_running_loop() -> None:
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return
    raise RuntimeError(
        "assess_sync() cannot be called from a running event loop; "
        "use `await fleet.assess(...)` instead."
    )


async def assess(request: str, *, config: FleetConfig | None = None) -> FleetResult:
    """Assess a request with a default (or supplied) fleet configuration."""
    return await Fleet(config).assess(request)


def assess_sync(request: str, *, config: FleetConfig | None = None) -> FleetResult:
    """Synchronous convenience wrapper around :func:`assess`."""
    return Fleet(config).assess_sync(request)


def list_roles(*, registry: RoleRegistry | None = None) -> tuple[RoleSpec, ...]:
    """The full security-department roster."""
    return (registry or REGISTRY).all()


def compose_report(
    request: str,
    triage: TriageDecision,
    agent_results: list[AgentResult],
    *,
    include_metadata: bool = True,
) -> FleetResult:
    """Assemble a :class:`FleetResult` from pre-computed pieces (no synthesis).

    Useful when a caller has already run roles and just wants the composed
    markdown report and usage rollup.
    """
    now = datetime.now(UTC)
    metadata: FleetMetadata | None = None
    if include_metadata:
        per_agent = [r.usage for r in agent_results]
        totals, grand = aggregate_usage(per_agent)
        metadata = FleetMetadata(
            per_agent=per_agent,
            totals_by_model=totals,
            grand_total=grand,
            started_at=now,
            finished_at=now,
        )
    report_md = build_report_md(request, triage, agent_results, None, metadata)
    return FleetResult(
        request=request,
        triage=triage,
        agent_results=agent_results,
        synthesis=None,
        report_md=report_md,
        metadata=metadata,
    )
