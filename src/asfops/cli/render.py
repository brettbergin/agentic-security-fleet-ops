"""Rich rendering helpers for the CLI."""

from __future__ import annotations

import threading

from rich.console import Console
from rich.table import Table

from asfops.fleet.roles import RoleSpec
from asfops.results import FleetEvent, FleetResult


def roster_table(roles: tuple[RoleSpec, ...]) -> Table:
    table = Table(title="Security Fleet Roster", show_lines=False, expand=True)
    table.add_column("Slug", style="cyan", no_wrap=True)
    table.add_column("Role", style="bold")
    table.add_column("Charter")
    for role in roles:
        table.add_row(role.slug, role.name, role.charter)
    return table


def metadata_table(result: FleetResult) -> Table | None:
    if result.metadata is None:
        return None
    table = Table(title="Usage by Model", expand=True)
    table.add_column("Model", style="cyan")
    table.add_column("Requests", justify="right")
    table.add_column("Input", justify="right")
    table.add_column("Output", justify="right")
    for t in result.metadata.totals_by_model:
        table.add_row(t.model_id, str(t.requests), str(t.input_tokens), str(t.output_tokens))
    g = result.metadata.grand_total
    table.add_row(
        "[bold]all[/bold]",
        f"[bold]{g.requests}[/bold]",
        f"[bold]{g.input_tokens}[/bold]",
        f"[bold]{g.output_tokens}[/bold]",
    )
    return table


class ProgressReporter:
    """Renders live per-role progress from fleet events.

    Kept deliberately simple (line-based, thread-safe) so it composes with any
    console and needs no live-refresh teardown.
    """

    def __init__(self, console: Console) -> None:
        self.console = console
        self._lock = threading.Lock()

    def __call__(self, event: FleetEvent) -> None:
        with self._lock:
            self._render(event)

    def _render(self, event: FleetEvent) -> None:
        c = self.console
        match event.kind:
            case "triage_started":
                c.print("[dim]Triaging request…[/dim]")
            case "triage_finished":
                c.print(f"[green]Triage selected:[/green] {event.detail}")
            case "agent_started":
                c.print(f"  [yellow]▶ {event.slug}[/yellow] running…")
            case "agent_finished":
                c.print(f"  [green]✓ {event.slug}[/green] done")
            case "agent_failed":
                c.print(f"  [red]✗ {event.slug}[/red] failed: {event.detail}")
            case "synthesis_started":
                c.print("[dim]Synthesizing report…[/dim]")
            case "synthesis_finished":
                detail = f" ({event.detail})" if event.detail else ""
                c.print(f"[green]Synthesis complete[/green]{detail}")
