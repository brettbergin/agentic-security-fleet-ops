"""Streamlit dashboard for the asfops fleet.

Run via ``asfops dashboard`` (or ``streamlit run .../dashboard/app.py``). This is
the view layer only — all parsing lives in :mod:`asfops.dashboard.data`.
"""

from __future__ import annotations

import pandas as pd
import streamlit as st

import asfops
from asfops import Fleet, FleetConfig
from asfops.dashboard.data import (
    SEVERITY_ORDER,
    RunRecord,
    finding_rows,
    list_runs,
    run_summary_rows,
    usage_rows,
)

_SEV_EMOJI = {
    "critical": "🟥",
    "high": "🟧",
    "medium": "🟨",
    "low": "🟩",
    "informational": "🟦",
}


def _severity_frame(counts: dict[str, int]) -> pd.DataFrame:
    data = [{"severity": s, "count": counts.get(s, 0)} for s in SEVERITY_ORDER]
    return pd.DataFrame(data).set_index("severity")


def _pick_run(runs: list[RunRecord], key: str) -> RunRecord | None:
    if not runs:
        st.info("No runs yet. Start one from **New assessment**, or run `asfops assess …`.")
        return None
    labels = {r.label: r for r in runs}
    choice = st.selectbox("Run", list(labels), key=key)
    return labels[choice]


# --------------------------------------------------------------------------- #
# Pages
# --------------------------------------------------------------------------- #


def page_runs(runs: list[RunRecord]) -> None:
    st.header("Runs")
    if not runs:
        st.info("No runs yet. Start one from **New assessment**, or run `asfops assess …`.")
        return
    df = pd.DataFrame(run_summary_rows(runs)).drop(columns=["run_id"])
    st.dataframe(df, width="stretch", hide_index=True)

    st.divider()
    run = _pick_run(runs, key="runs_detail")
    if run is not None:
        _render_run_detail(run)


def _render_run_detail(run: RunRecord) -> None:
    st.subheader(run.label)
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Specialists", run.agent_count)
    c2.metric("Succeeded", run.ok_count, delta=-len(run.failed) or None)
    c3.metric("Findings", sum(run.severity_counts().values()))
    c4.metric("Tokens", f"{run.total_input_tokens + run.total_output_tokens:,}")
    if run.request_chars:
        st.caption(f"Input: {run.request_chars:,} chars · wall time {run.duration_s or 0:.0f}s")
    if run.failed:
        st.warning("Failed: " + ", ".join(run.failed))

    if run.synthesis:
        st.markdown("#### Executive summary")
        st.write(run.synthesis.executive_summary)
        if run.synthesis.top_risks:
            st.markdown("**Top risks**")
            for r in run.synthesis.top_risks:
                st.markdown(f"- {r}")

    st.markdown("#### Findings by severity")
    st.bar_chart(_severity_frame(run.severity_counts()))

    if run.triage:
        with st.expander("Triage decision"):
            tri = pd.DataFrame(
                [
                    {"slug": s.slug, "priority": s.priority, "rationale": s.rationale}
                    for s in run.triage.selected
                ]
            )
            st.dataframe(tri, width="stretch", hide_index=True)

    st.markdown("#### Specialist reports")
    for a in run.agents:
        header = f"{_status_icon(a)} {a.role_name} — {a.finding_count} findings ({a.status})"
        with st.expander(header):
            if a.report is None:
                st.error(a.error or "failed")
                continue
            st.caption(
                f"{a.model_id} · {a.input_tokens:,} in / {a.output_tokens:,} out · "
                f"{a.duration_s:.0f}s · confidence {a.report.confidence}"
            )
            st.write(a.report.summary)
            for f in sorted(
                a.report.findings, key=lambda f: SEVERITY_ORDER.index(f.severity.value)
            ):
                st.markdown(
                    f"{_SEV_EMOJI.get(f.severity.value, '')} **[{f.severity.value.upper()}] "
                    f"{f.title}**"
                )
                st.markdown(f.description)
                st.markdown(f"*Recommendation:* {f.recommendation}")


def _status_icon(a: object) -> str:
    return "✅" if getattr(a, "ok", False) else "❌"


def page_findings(runs: list[RunRecord]) -> None:
    st.header("Findings explorer")
    run = _pick_run(runs, key="findings_run")
    if run is None:
        return
    rows = finding_rows(run)
    if not rows:
        st.info("No findings in this run.")
        return
    df = pd.DataFrame(rows)
    severities = st.multiselect("Severity", SEVERITY_ORDER, default=SEVERITY_ORDER)
    roles = sorted(df["role"].unique())
    picked_roles = st.multiselect("Role", roles, default=roles)
    view = df[df["severity"].isin(severities) & df["role"].isin(picked_roles)]
    st.caption(f"{len(view)} of {len(df)} findings")
    st.dataframe(
        view[["severity", "title", "role", "recommendation"]],
        width="stretch",
        hide_index=True,
    )


def page_usage(runs: list[RunRecord]) -> None:
    st.header("Usage & cost")
    run = _pick_run(runs, key="usage_run")
    if run is None:
        return
    rows = usage_rows(run)
    if not rows:
        st.info("No usage recorded.")
        return
    df = pd.DataFrame(rows)
    st.dataframe(df, width="stretch", hide_index=True)
    chart = df.set_index("slug")[["input_tokens", "output_tokens"]]
    st.bar_chart(chart)

    st.markdown("#### Tokens across runs")
    trend = pd.DataFrame(run_summary_rows(runs))[["run", "tokens"]].set_index("run")
    st.bar_chart(trend)


def page_roster() -> None:
    st.header("The fleet")
    df = pd.DataFrame(
        [
            {"slug": r.slug, "role": r.name, "charter": r.charter, "tags": ", ".join(r.tags)}
            for r in asfops.list_roles()
        ]
    )
    st.dataframe(df, width="stretch", hide_index=True)


def page_new_assessment() -> None:
    st.header("New assessment")
    st.caption(
        "Runs the fleet on Copilot (or your configured model). This blocks the app "
        "for a few minutes; the run then appears under **Runs**."
    )
    request = st.text_area(
        "Assessment request", height=200, placeholder="Paste a design, diff, issue…"
    )
    model = st.text_input("Model", value="copilot:claude-sonnet-4.5")
    slugs = [r.slug for r in asfops.list_roles()]
    force = st.multiselect("Force roles", slugs)
    exclude = st.multiselect("Exclude roles", slugs)
    concurrency = st.slider("Max concurrency", 1, len(slugs), 8)

    if st.button("Run assessment", type="primary", disabled=not request.strip()):
        config = FleetConfig(
            default_model=model,
            force_roles=tuple(force),
            exclude_roles=tuple(exclude),
            max_concurrency=concurrency,
        )
        with st.status("Running the fleet…", expanded=True) as status:
            try:
                result = Fleet(config).assess_sync(request)
            except Exception as exc:
                status.update(label="Failed", state="error")
                st.exception(exc)
                return
            status.update(label="Done", state="complete")
        st.success(f"{len(result.agent_results)} specialists reported.")
        st.markdown(result.report_md)


# --------------------------------------------------------------------------- #
# Entrypoint
# --------------------------------------------------------------------------- #


def main() -> None:
    st.set_page_config(page_title="asfops fleet", page_icon="🛡️", layout="wide")
    st.sidebar.title("🛡️ asfops")
    st.sidebar.caption(f"v{asfops.__version__}")
    page = st.sidebar.radio(
        "View",
        ["Runs", "Findings", "Usage", "Roster", "New assessment"],
    )
    if st.sidebar.button("↻ Refresh"):
        st.rerun()

    if page == "Roster":
        page_roster()
        return
    if page == "New assessment":
        page_new_assessment()
        return

    runs = list_runs()
    if page == "Runs":
        page_runs(runs)
    elif page == "Findings":
        page_findings(runs)
    elif page == "Usage":
        page_usage(runs)


main()
