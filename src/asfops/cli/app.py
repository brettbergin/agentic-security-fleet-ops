"""The asfops command-line interface (typer + rich)."""

from __future__ import annotations

import asyncio
import os
import sys
from enum import StrEnum
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.markdown import Markdown
from rich.markup import escape

from asfops._version import __version__
from asfops.api import Fleet
from asfops.cli.render import ProgressReporter, metadata_table, roster_table
from asfops.config import FleetConfig
from asfops.exceptions import AsfopsError, RoleNotFoundError
from asfops.logs import LoggingConfig, configure_logging, ensure_app_home
from asfops.results import AgentResult, FleetResult, build_agent_report_md

app = typer.Typer(
    name="asfops",
    help="Agentic Security Fleet Ops — a security department of LLM agents.",
    no_args_is_help=True,
    add_completion=False,
)

_stdout = Console()
_stderr = Console(stderr=True)


@app.callback()
def _startup() -> None:
    """Runs before any command: ensure the ~/.asfops home directory exists."""
    # Skip under pytest so the test suite never touches the real home directory.
    if "PYTEST_CURRENT_TEST" not in os.environ:
        ensure_app_home()


class OutputFormat(StrEnum):
    md = "md"
    json = "json"


class RosterFormat(StrEnum):
    table = "table"
    json = "json"


def _read_request(request: str | None, file: Path | None) -> str:
    if file is not None:
        return file.read_text(encoding="utf-8")
    if request in (None, "-"):
        data = sys.stdin.read()
        if not data.strip():
            _fail("No request provided (empty stdin).")
        return data
    assert request is not None
    return request


def _fail(message: str, code: int = 1) -> None:
    # escape() so bracketed content (paths, "asfops[dashboard]") isn't eaten as
    # rich markup.
    _stderr.print(f"[red]error:[/red] {escape(message)}")
    raise typer.Exit(code)


async def _assess_and_close(fleet: Fleet, text: str, reporter: object) -> FleetResult:
    # Run the assessment and shut the shared Copilot client down inside the SAME
    # event loop — stopping it from a second asyncio.run() fails (loop closed).
    try:
        return await fleet.assess(text, on_event=reporter)  # type: ignore[arg-type]
    finally:
        await fleet.aclose()


async def _run_role_and_close(fleet: Fleet, slug: str, text: str) -> AgentResult:
    try:
        return await fleet.run_role(slug, text)
    finally:
        await fleet.aclose()


def _build_config(
    model: str | None,
    triage_model: str | None,
    roles: list[str] | None,
    exclude: list[str] | None,
    concurrency: int | None,
    timeout: float | None,
    no_metadata: bool,
    log_dir: Path | None = None,
    log_level: str = "INFO",
    no_logs: bool = False,
) -> FleetConfig:
    cfg = FleetConfig()
    if model:
        cfg.default_model = model
    if triage_model:
        cfg.triage_model = triage_model
    if roles:
        cfg.force_roles = tuple(roles)
    if exclude:
        cfg.exclude_roles = tuple(exclude)
    if concurrency:
        cfg.max_concurrency = concurrency
    if timeout:
        cfg.per_agent_timeout_s = timeout
    cfg.include_metadata = not no_metadata
    cfg.logging = LoggingConfig(
        enabled=not no_logs,
        base_dir=log_dir if log_dir is not None else cfg.logging.base_dir,
        level=log_level.upper(),
    )
    return cfg


@app.command()
def assess(
    request: Annotated[
        str | None, typer.Argument(help="The assessment request text, or '-' for stdin.")
    ] = None,
    file: Annotated[
        Path | None, typer.Option("--file", "-f", help="Read the request from a file.")
    ] = None,
    model: Annotated[
        str | None, typer.Option("--model", "-m", help="Default model ref for all agents.")
    ] = None,
    triage_model: Annotated[
        str | None, typer.Option("--triage-model", help="Model ref for the triage step.")
    ] = None,
    role: Annotated[
        list[str] | None, typer.Option("--role", "-r", help="Force a role (repeatable).")
    ] = None,
    exclude: Annotated[
        list[str] | None, typer.Option("--exclude", "-x", help="Exclude a role (repeatable).")
    ] = None,
    concurrency: Annotated[
        int | None, typer.Option("--concurrency", "-c", help="Max concurrent agents.")
    ] = None,
    timeout: Annotated[
        float | None, typer.Option("--timeout", help="Per-agent timeout (seconds).")
    ] = None,
    output_format: Annotated[
        OutputFormat, typer.Option("--format", help="Output format.")
    ] = OutputFormat.md,
    output: Annotated[
        Path | None, typer.Option("--output", "-o", help="Write output to a file.")
    ] = None,
    no_metadata: Annotated[
        bool, typer.Option("--no-metadata", help="Omit usage metadata.")
    ] = False,
    log_dir: Annotated[
        Path | None, typer.Option("--log-dir", help="Base directory for log output.")
    ] = None,
    log_level: Annotated[
        str, typer.Option("--log-level", help="Log level (DEBUG/INFO/WARNING/ERROR).")
    ] = "INFO",
    no_logs: Annotated[bool, typer.Option("--no-logs", help="Disable all logging.")] = False,
    quiet: Annotated[bool, typer.Option("--quiet", "-q", help="Suppress progress output.")] = False,
) -> None:
    """Run a full fleet assessment and print the composed report."""
    text = _read_request(request, file)
    cfg = _build_config(
        model,
        triage_model,
        role,
        exclude,
        concurrency,
        timeout,
        no_metadata,
        log_dir,
        log_level,
        no_logs,
    )
    configure_logging(cfg.logging)
    fleet = Fleet(cfg)

    # Progress goes to stderr (line-based, never touches the stdout report or the
    # -o file), so show it for every format/output unless explicitly quieted.
    reporter = ProgressReporter(_stderr) if not quiet else None

    try:
        result = asyncio.run(_assess_and_close(fleet, text, reporter))
    except AsfopsError as exc:
        _fail(str(exc))
        return

    if not no_logs and not quiet:
        _stderr.print(f"[dim]Logs written under {cfg.logging.base_dir}/[/dim]")

    if output_format is OutputFormat.json:
        payload = result.model_dump_json(indent=2)
        _emit(payload, output)
        return

    if output is not None:
        _emit(result.report_md, output)
        return

    _stdout.print(Markdown(result.report_md))
    table = metadata_table(result)
    if table is not None and not no_metadata:
        _stdout.print(table)


@app.command()
def run(
    slug: Annotated[str, typer.Argument(help="Role slug to engage (see `asfops roster`).")],
    request: Annotated[
        str | None, typer.Argument(help="The request text, or '-' for stdin.")
    ] = None,
    file: Annotated[Path | None, typer.Option("--file", "-f")] = None,
    model: Annotated[str | None, typer.Option("--model", "-m")] = None,
    output_format: Annotated[
        OutputFormat, typer.Option("--format", help="Output format.")
    ] = OutputFormat.md,
    log_dir: Annotated[
        Path | None, typer.Option("--log-dir", help="Base directory for log output.")
    ] = None,
    log_level: Annotated[str, typer.Option("--log-level", help="Log level.")] = "INFO",
    no_logs: Annotated[bool, typer.Option("--no-logs", help="Disable all logging.")] = False,
) -> None:
    """Engage a single specialist directly (no triage, no synthesis)."""
    text = _read_request(request, file)
    cfg = FleetConfig()
    if model:
        cfg.default_model = model
    cfg.logging = LoggingConfig(
        enabled=not no_logs,
        base_dir=log_dir if log_dir is not None else cfg.logging.base_dir,
        level=log_level.upper(),
    )
    configure_logging(cfg.logging)
    fleet = Fleet(cfg)
    try:
        result = asyncio.run(_run_role_and_close(fleet, slug, text))
    except RoleNotFoundError as exc:
        _fail(str(exc), code=2)
        return
    except AsfopsError as exc:
        _fail(str(exc))
        return

    if output_format is OutputFormat.json:
        _stdout.print_json(result.model_dump_json())
        return
    if result.report is None:
        _fail(f"{slug} failed: {result.error}")
        return
    _stdout.print(Markdown(build_agent_report_md(result.role_name, result.report)))


@app.command()
def roster(
    output_format: Annotated[
        RosterFormat, typer.Option("--format", help="Output format.")
    ] = RosterFormat.table,
) -> None:
    """List the security specialists in the fleet."""
    roles = Fleet().roster()
    if output_format is RosterFormat.json:
        import json

        _stdout.print_json(
            json.dumps(
                [
                    {"slug": r.slug, "name": r.name, "charter": r.charter, "tags": list(r.tags)}
                    for r in roles
                ]
            )
        )
        return
    _stdout.print(roster_table(roles))


@app.command()
def models() -> None:
    """Check GitHub Copilot availability and list available models."""
    try:
        from copilot import CopilotClient
    except ImportError:
        _fail("github-copilot-sdk is not installed.")
        return

    async def _list() -> list[str]:
        client = CopilotClient(log_level="error")
        await client.start()
        try:
            infos = await client.list_models()
            return [getattr(m, "id", str(m)) for m in infos]
        finally:
            await client.stop()

    try:
        ids = asyncio.run(_list())
    except Exception as exc:
        _stderr.print(f"[yellow]Copilot runtime unavailable:[/yellow] {exc}")
        _stdout.print(
            "You can still run the fleet on any pydantic-ai model, e.g. "
            "[cyan]--model openai:gpt-5.2[/cyan] or "
            "[cyan]--model anthropic:claude-sonnet-4-5[/cyan]."
        )
        raise typer.Exit(0) from None
    _stdout.print("[green]Copilot runtime OK.[/green] Available models:")
    for mid in ids:
        _stdout.print(f"  • copilot:{mid}")


@app.command()
def dashboard(
    port: Annotated[int, typer.Option("--port", "-p", help="Port to serve on.")] = 8501,
    headless: Annotated[
        bool, typer.Option("--headless", help="Don't auto-open a browser.")
    ] = False,
) -> None:
    """Launch the Streamlit dashboard over the ~/.asfops/logs run history."""
    from asfops.dashboard.launch import DashboardNotInstalledError, launch

    try:
        raise typer.Exit(launch(port=port, headless=headless))
    except DashboardNotInstalledError as exc:
        _fail(str(exc), code=2)


@app.command()
def version() -> None:
    """Print the asfops version."""
    _stdout.print(__version__)


def _emit(content: str, output: Path | None) -> None:
    if output is not None:
        output.write_text(content, encoding="utf-8")
        _stderr.print(f"[green]Wrote[/green] {output}")
    else:
        # plain stdout, no rich formatting (pipe-friendly)
        sys.stdout.write(content)
        if not content.endswith("\n"):
            sys.stdout.write("\n")


def main() -> None:
    app()


if __name__ == "__main__":
    main()
