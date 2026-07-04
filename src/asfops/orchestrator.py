"""The Security Orchestrator: triage, fan-out, and synthesis."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable
from datetime import UTC, datetime

from pydantic_ai import Agent
from pydantic_ai.models import Model

from asfops.config import DEFAULT_TRIAGE_FALLBACK, FleetConfig
from asfops.exceptions import TriageError
from asfops.fleet.member import build_agent
from asfops.fleet.roles import REGISTRY, RoleRegistry
from asfops.fleet.schemas import (
    AgentReport,
    RoleSelection,
    SynthesisSummary,
    TriageDecision,
)
from asfops.logs import RunLogger, get_logger
from asfops.models.resolve import resolve_model
from asfops.results import (
    AgentResult,
    AgentUsage,
    FleetEvent,
    FleetMetadata,
    FleetResult,
    aggregate_usage,
    build_report_md,
    usage_from_run,
)

EventCallback = Callable[[FleetEvent], None]

log = get_logger("orchestrator")


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


_TRIAGE_SYSTEM = """
You are the Security Orchestrator for a security department. Given an assessment
request, decide which security specialists should review it. Choose only roles
whose expertise is genuinely relevant — engaging every role dilutes quality.
Mark each as "primary" (core to the request) or "supporting" (adds a valuable
secondary perspective). Prefer 3-7 roles for a focused request; more only when
the request is broad. Use each role's exact slug.
""".strip()

_SYNTHESIS_SYSTEM = """
You are the Security Orchestrator composing the executive layer of a security
report from your specialists' individual reports. Write a sharp executive
summary, rank the top risks across all specialists (highest first), note themes
that more than one specialist independently raised, and give ordered, concrete
next steps. Do not invent findings that no specialist reported.
""".strip()


def _roster_block(registry: RoleRegistry) -> str:
    lines = ["Available roles (slug — name: charter | tags):"]
    for role in registry.all():
        lines.append(f"- {role.slug} — {role.name}: {role.charter} | {', '.join(role.tags)}")
    return "\n".join(lines)


class Orchestrator:
    """Runs the full assessment: triage, fan-out, synthesis."""

    def __init__(
        self,
        config: FleetConfig | None = None,
        *,
        registry: RoleRegistry | None = None,
    ) -> None:
        self.config = config or FleetConfig()
        self.registry = registry or REGISTRY

    def _model(self, ref: object) -> Model:
        primary = resolve_model(ref)  # type: ignore[arg-type]
        if not self.config.fallback_models:
            return primary
        from pydantic_ai.exceptions import ModelAPIError
        from pydantic_ai.models.fallback import FallbackModel

        from asfops.exceptions import CopilotRuntimeError

        fallbacks = [resolve_model(f) for f in self.config.fallback_models]
        # Fall back on transient model/API errors and Copilot runtime failures,
        # but not on programming errors (which should surface loudly).
        return FallbackModel(primary, *fallbacks, fallback_on=(ModelAPIError, CopilotRuntimeError))

    async def triage(
        self, request: str, *, on_event: EventCallback | None = None
    ) -> TriageDecision:
        decision, _usage = await self._triage(request, on_event=on_event)
        return decision

    async def _triage(
        self,
        request: str,
        *,
        on_event: EventCallback | None = None,
        run_logger: RunLogger | None = None,
    ) -> tuple[TriageDecision, AgentUsage]:
        if on_event:
            on_event(FleetEvent(kind="triage_started"))
        model = self._model(self.config.triage_model_ref())
        model_id = f"{model.system}:{model.model_name}"
        agent: Agent[None, TriageDecision] = Agent(
            model=model,
            output_type=TriageDecision,
            system_prompt=f"{_TRIAGE_SYSTEM}\n\n{_roster_block(self.registry)}",
            name="triage",
        )
        if run_logger is not None:
            run_logger.log.info("triage_started", model_id=model_id)
        started_at = _now_iso()
        start = time.monotonic()
        result = await agent.run(
            request,
            model_settings=self.config.model_settings(),
            usage_limits=self.config.usage_limits(),
        )
        duration = time.monotonic() - start
        usage = usage_from_run("triage", model_id, result.usage, duration)
        decision = self._reconcile_selection(result.output)
        if run_logger is not None:
            run_logger.agent_log(
                slug="triage",
                role_name="Triage",
                model_id=model_id,
                run=result,
                duration_s=duration,
                started_at=started_at,
            )
            run_logger.log.info(
                "triage_finished",
                selected=[s.slug for s in decision.selected],
                duration_s=round(duration, 3),
            )
        if on_event:
            on_event(
                FleetEvent(
                    kind="triage_finished",
                    detail=", ".join(s.slug for s in decision.selected),
                )
            )
        return decision, usage

    def _reconcile_selection(self, decision: TriageDecision) -> TriageDecision:
        cfg = self.config
        seen: set[str] = set()
        selected: list[RoleSelection] = []
        for sel in decision.selected:
            if sel.slug not in self.registry or sel.slug in cfg.exclude_roles:
                continue
            if sel.slug in seen:
                continue
            seen.add(sel.slug)
            selected.append(sel)
        for slug in cfg.force_roles:
            if slug in self.registry and slug not in cfg.exclude_roles and slug not in seen:
                seen.add(slug)
                selected.append(
                    RoleSelection(
                        slug=slug, rationale="Forced by configuration.", priority="primary"
                    )
                )
        if not selected:
            if cfg.on_empty_triage == "error":
                raise TriageError("Triage selected no usable roles.")
            for slug in DEFAULT_TRIAGE_FALLBACK:
                if slug in self.registry and slug not in cfg.exclude_roles:
                    selected.append(
                        RoleSelection(
                            slug=slug,
                            rationale="Default core reviewer (triage fallback).",
                            priority="primary",
                        )
                    )
        return TriageDecision(selected=selected, overall_rationale=decision.overall_rationale)

    async def _run_role(
        self,
        sel: RoleSelection,
        request: str,
        *,
        on_event: EventCallback | None,
        run_logger: RunLogger | None = None,
    ) -> AgentResult:
        role = self.registry.get(sel.slug)
        model_ref = self.config.model_overrides.get(sel.slug) or role.default_model
        model = self._model(model_ref if model_ref is not None else self.config.default_model)
        model_id = f"{model.system}:{model.model_name}"
        if on_event:
            on_event(FleetEvent(kind="agent_started", slug=sel.slug))
        if run_logger is not None:
            run_logger.log.info("agent_started", slug=sel.slug, model_id=model_id)
        started_at = _now_iso()
        start = time.monotonic()
        try:
            agent = build_agent(role, model)
            async with asyncio.timeout(self.config.per_agent_timeout_s):
                run = await agent.run(
                    request,
                    model_settings=self.config.model_settings(),
                    usage_limits=self.config.usage_limits(),
                )
            duration = time.monotonic() - start
            report: AgentReport = run.output
            usage = usage_from_run(sel.slug, model_id, run.usage, duration)
            if run_logger is not None:
                run_logger.agent_log(
                    slug=sel.slug,
                    role_name=role.name,
                    model_id=model_id,
                    run=run,
                    duration_s=duration,
                    started_at=started_at,
                )
                run_logger.log.info(
                    "agent_finished",
                    slug=sel.slug,
                    model_id=model_id,
                    duration_s=round(duration, 3),
                    findings=len(report.findings),
                    input_tokens=usage.input_tokens,
                    output_tokens=usage.output_tokens,
                )
            if on_event:
                on_event(FleetEvent(kind="agent_finished", slug=sel.slug))
            return AgentResult(
                role_slug=sel.slug,
                role_name=role.name,
                model_id=model_id,
                report=report,
                duration_s=duration,
                usage=usage,
            )
        except Exception as exc:
            duration = time.monotonic() - start
            if run_logger is not None:
                run_logger.agent_log(
                    slug=sel.slug,
                    role_name=role.name,
                    model_id=model_id,
                    duration_s=duration,
                    started_at=started_at,
                    error=f"{type(exc).__name__}: {exc}",
                )
                run_logger.log.warning(
                    "agent_failed",
                    slug=sel.slug,
                    model_id=model_id,
                    error=str(exc),
                    exc_info=exc,
                )
            if on_event:
                on_event(FleetEvent(kind="agent_failed", slug=sel.slug, detail=str(exc)))
            return AgentResult(
                role_slug=sel.slug,
                role_name=role.name,
                model_id=model_id,
                error=f"{type(exc).__name__}: {exc}",
                duration_s=duration,
                usage=AgentUsage(slug=sel.slug, model_id=model_id, duration_s=duration),
            )

    async def fan_out(
        self,
        decision: TriageDecision,
        request: str,
        *,
        on_event: EventCallback | None = None,
        run_logger: RunLogger | None = None,
    ) -> list[AgentResult]:
        sem = asyncio.Semaphore(self.config.max_concurrency)

        async def guarded(sel: RoleSelection) -> AgentResult:
            async with sem:
                return await self._run_role(sel, request, on_event=on_event, run_logger=run_logger)

        return await asyncio.gather(*(guarded(sel) for sel in decision.selected))

    async def synthesize(
        self,
        request: str,
        agent_results: list[AgentResult],
        *,
        on_event: EventCallback | None = None,
        run_logger: RunLogger | None = None,
    ) -> tuple[SynthesisSummary | None, AgentUsage | None]:
        ok_results = [r for r in agent_results if r.report is not None]
        if not ok_results:
            return None, None
        if on_event:
            on_event(FleetEvent(kind="synthesis_started"))
        model = self._model(self.config.synthesis_model_ref())
        model_id = f"{model.system}:{model.model_name}"
        agent: Agent[None, SynthesisSummary] = Agent(
            model=model,
            output_type=SynthesisSummary,
            system_prompt=_SYNTHESIS_SYSTEM,
            name="synthesis",
        )
        if run_logger is not None:
            run_logger.log.info("synthesis_started", model_id=model_id)
        prompt = self._synthesis_prompt(request, ok_results)
        started_at = _now_iso()
        start = time.monotonic()
        try:
            run = await agent.run(
                prompt,
                model_settings=self.config.model_settings(),
                usage_limits=self.config.usage_limits(),
            )
        except Exception as exc:
            if run_logger is not None:
                run_logger.log.warning("synthesis_failed", error=str(exc), exc_info=exc)
            if on_event:
                on_event(FleetEvent(kind="synthesis_finished", detail="failed"))
            return None, None
        duration = time.monotonic() - start
        usage = usage_from_run("synthesis", model_id, run.usage, duration)
        if run_logger is not None:
            run_logger.agent_log(
                slug="synthesis",
                role_name="Synthesis",
                model_id=model_id,
                run=run,
                duration_s=duration,
                started_at=started_at,
            )
            run_logger.log.info("synthesis_finished", duration_s=round(duration, 3))
        if on_event:
            on_event(FleetEvent(kind="synthesis_finished"))
        return run.output, usage

    @staticmethod
    def _synthesis_prompt(request: str, ok_results: list[AgentResult]) -> str:
        parts = [f"Assessment request:\n{request}", "", "Specialist reports:"]
        for r in ok_results:
            assert r.report is not None
            findings = (
                "; ".join(f"[{f.severity.value}] {f.title}" for f in r.report.findings)
                or "no discrete findings"
            )
            parts.append(f"\n## {r.role_name}\nSummary: {r.report.summary}\nFindings: {findings}")
        return "\n".join(parts)

    async def run(
        self,
        request: str,
        *,
        on_event: EventCallback | None = None,
        run_logger: RunLogger | None = None,
    ) -> FleetResult:
        owns_logger = run_logger is None
        if run_logger is None:
            run_logger = RunLogger(self.config.logging)
        try:
            run_logger.log.info("run_started", request_chars=len(request))
            started_at = datetime.now(UTC)
            decision, triage_usage = await self._triage(
                request, on_event=on_event, run_logger=run_logger
            )
            agent_results = await self.fan_out(
                decision, request, on_event=on_event, run_logger=run_logger
            )
            synthesis, synth_usage = await self.synthesize(
                request, agent_results, on_event=on_event, run_logger=run_logger
            )
            finished_at = datetime.now(UTC)

            metadata: FleetMetadata | None = None
            if self.config.include_metadata:
                per_agent = [triage_usage, *(r.usage for r in agent_results)]
                if synth_usage is not None:
                    per_agent = [*per_agent, synth_usage]
                totals, grand = aggregate_usage(per_agent)
                metadata = FleetMetadata(
                    per_agent=per_agent,
                    totals_by_model=totals,
                    grand_total=grand,
                    started_at=started_at,
                    finished_at=finished_at,
                )

            report_md = build_report_md(request, decision, agent_results, synthesis, metadata)
            failures = [r.role_slug for r in agent_results if r.report is None]
            run_logger.log.info(
                "run_finished",
                agents=len(agent_results),
                failed=failures,
                duration_s=round((finished_at - started_at).total_seconds(), 3),
            )
            return FleetResult(
                request=request,
                triage=decision,
                agent_results=agent_results,
                synthesis=synthesis,
                report_md=report_md,
                metadata=metadata,
            )
        finally:
            if owns_logger:
                run_logger.close()
