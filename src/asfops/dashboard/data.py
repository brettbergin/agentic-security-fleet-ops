"""Parse the ``~/.asfops/logs`` run corpus into typed records.

Pure and Streamlit-free so it is unit-testable. Each run directory holds a
structlog ``app.log`` (JSON lines) and ``agents/<slug>.json`` files (each an
agent's full context + its structured output); this module reconstructs typed
:class:`RunRecord` objects from them, reusing the fleet schemas.
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from asfops.fleet.schemas import AgentReport, Severity, SynthesisSummary, TriageDecision
from asfops.logs import default_log_dir

_SPECIAL = {"triage", "synthesis"}


@dataclass
class AgentRecord:
    """One specialist's parsed result within a run."""

    slug: str
    role_name: str
    model_id: str
    status: str  # "ok" | "failed"
    error: str | None
    duration_s: float
    input_tokens: int
    output_tokens: int
    report: AgentReport | None

    @property
    def ok(self) -> bool:
        return self.status == "ok" and self.report is not None

    @property
    def finding_count(self) -> int:
        return len(self.report.findings) if self.report else 0

    def severity_counts(self) -> dict[str, int]:
        if not self.report:
            return {}
        return dict(Counter(f.severity.value for f in self.report.findings))


@dataclass
class RunRecord:
    """A fully parsed assessment run."""

    run_id: str
    run_dir: Path
    started_at: datetime | None
    request_chars: int | None
    triage: TriageDecision | None
    agents: list[AgentRecord]
    synthesis: SynthesisSummary | None
    failed: list[str]
    duration_s: float | None

    # --- convenience rollups ------------------------------------------------
    @property
    def label(self) -> str:
        ts = self.started_at.strftime("%Y-%m-%d %H:%M") if self.started_at else "?"
        return f"{ts} · {self.run_id[:8]}"

    @property
    def agent_count(self) -> int:
        return len(self.agents)

    @property
    def ok_count(self) -> int:
        return sum(1 for a in self.agents if a.ok)

    @property
    def total_input_tokens(self) -> int:
        return sum(a.input_tokens for a in self.agents)

    @property
    def total_output_tokens(self) -> int:
        return sum(a.output_tokens for a in self.agents)

    def severity_counts(self) -> dict[str, int]:
        counts: Counter[str] = Counter()
        for a in self.agents:
            counts.update(a.severity_counts())
        return dict(counts)


def _read_app_log(run_dir: Path) -> tuple[dict[str, Any], dict[str, Any], datetime | None]:
    """Return (run_started fields, run_finished fields, first-line timestamp)."""
    started: dict[str, Any] = {}
    finished: dict[str, Any] = {}
    first_ts: datetime | None = None
    path = run_dir / "app.log"
    if not path.exists():
        return started, finished, first_ts
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        if first_ts is None and rec.get("timestamp"):
            first_ts = _parse_ts(rec["timestamp"])
        event = rec.get("event")
        if event == "run_started":
            started = rec
        elif event == "run_finished":
            finished = rec
    return started, finished, first_ts


def _parse_ts(value: str) -> datetime | None:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _ts_from_dir_name(run_dir: Path) -> datetime | None:
    # "<YYYYmmddTHHMMSSZ>-<runid8>"
    stamp = run_dir.name.split("-", 1)[0]
    try:
        return datetime.strptime(stamp, "%Y%m%dT%H%M%SZ").replace(tzinfo=UTC)
    except ValueError:
        return None


def _load_agent_json(path: Path) -> dict[str, Any] | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))  # type: ignore[no-any-return]
    except (OSError, json.JSONDecodeError):
        return None


def _agent_record(data: dict[str, Any]) -> AgentRecord:
    usage = data.get("usage") or {}
    report: AgentReport | None = None
    if data.get("status") == "ok" and data.get("output"):
        try:
            report = AgentReport.model_validate(data["output"])
        except Exception:
            report = None
    return AgentRecord(
        slug=data.get("slug", "?"),
        role_name=data.get("role_name", data.get("slug", "?")),
        model_id=data.get("model_id", "?"),
        status=data.get("status", "unknown"),
        error=data.get("error"),
        duration_s=float(data.get("duration_s") or 0.0),
        input_tokens=int(usage.get("input_tokens") or 0),
        output_tokens=int(usage.get("output_tokens") or 0),
        report=report,
    )


def load_run(run_dir: Path) -> RunRecord:
    """Parse a single run directory into a :class:`RunRecord`."""
    run_dir = Path(run_dir)
    started, finished, first_ts = _read_app_log(run_dir)
    agents_dir = run_dir / "agents"

    triage: TriageDecision | None = None
    synthesis: SynthesisSummary | None = None
    agents: list[AgentRecord] = []

    if agents_dir.is_dir():
        for path in sorted(agents_dir.glob("*.json")):
            slug = path.stem
            data = _load_agent_json(path)
            if data is None:
                continue
            if slug == "triage" and data.get("output"):
                try:
                    triage = TriageDecision.model_validate(data["output"])
                except Exception:
                    triage = None
            elif slug == "synthesis" and data.get("output"):
                try:
                    synthesis = SynthesisSummary.model_validate(data["output"])
                except Exception:
                    synthesis = None
            if slug not in _SPECIAL:
                agents.append(_agent_record(data))

    run_id = str(started.get("run_id") or finished.get("run_id") or run_dir.name)
    return RunRecord(
        run_id=run_id,
        run_dir=run_dir,
        started_at=first_ts or _ts_from_dir_name(run_dir),
        request_chars=started.get("request_chars"),
        triage=triage,
        agents=agents,
        synthesis=synthesis,
        failed=list(finished.get("failed") or [a.slug for a in agents if not a.ok]),
        duration_s=finished.get("duration_s"),
    )


def list_runs(base_dir: Path | None = None) -> list[RunRecord]:
    """Parse every run under ``base_dir`` (default ``~/.asfops/logs``), newest first."""
    base = Path(base_dir) if base_dir is not None else default_log_dir()
    if not base.is_dir():
        return []
    run_dirs = [p for p in base.iterdir() if p.is_dir() and (p / "app.log").exists()]
    runs = [load_run(p) for p in run_dirs]
    runs.sort(key=lambda r: r.started_at or datetime.min.replace(tzinfo=UTC), reverse=True)
    return runs


# --- table/chart rows (pandas-free; the app wraps these in DataFrames) -------


def run_summary_rows(runs: list[RunRecord]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for r in runs:
        sev = r.severity_counts()
        rows.append(
            {
                "run": r.label,
                "run_id": r.run_id,
                "started_at": r.started_at,
                "agents": r.agent_count,
                "ok": r.ok_count,
                "failed": len(r.failed),
                "findings": sum(sev.values()),
                "critical": sev.get("critical", 0),
                "high": sev.get("high", 0),
                "tokens": r.total_input_tokens + r.total_output_tokens,
                "duration_s": r.duration_s,
            }
        )
    return rows


def finding_rows(run: RunRecord) -> list[dict[str, Any]]:
    """Flatten every finding in a run for the findings explorer."""
    order = {s.value: i for i, s in enumerate(Severity)}
    rows: list[dict[str, Any]] = []
    for a in run.agents:
        if not a.report:
            continue
        for f in a.report.findings:
            rows.append(
                {
                    "role": a.role_name,
                    "slug": a.slug,
                    "severity": f.severity.value,
                    "title": f.title,
                    "description": f.description,
                    "recommendation": f.recommendation,
                    "references": ", ".join(f.references),
                }
            )
    rows.sort(key=lambda r: order.get(r["severity"], 99))
    return rows


def usage_rows(run: RunRecord) -> list[dict[str, Any]]:
    return [
        {
            "role": a.role_name,
            "slug": a.slug,
            "model": a.model_id,
            "input_tokens": a.input_tokens,
            "output_tokens": a.output_tokens,
            "duration_s": round(a.duration_s, 1),
            "status": a.status,
        }
        for a in run.agents
    ]


SEVERITY_ORDER: list[str] = [s.value for s in Severity]
"""Canonical severity ordering for charts (critical → informational)."""

__all__ = [
    "SEVERITY_ORDER",
    "AgentRecord",
    "RunRecord",
    "finding_rows",
    "list_runs",
    "load_run",
    "run_summary_rows",
    "usage_rows",
]
