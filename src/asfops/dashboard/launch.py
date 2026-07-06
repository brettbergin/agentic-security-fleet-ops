"""Launch the Streamlit dashboard as a subprocess.

Streamlit-free import: this only shells out to ``streamlit run``, so importing
it never pulls Streamlit in (the CLI can import it to give a friendly error
when the ``dashboard`` extra is not installed).
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

from asfops.exceptions import AsfopsError


class DashboardNotInstalledError(AsfopsError):
    """The optional ``dashboard`` extra (Streamlit) is not installed."""

    def __init__(self) -> None:
        super().__init__(
            "The dashboard requires the optional extra. Install it with:\n"
            "    pip install 'asfops[dashboard]'   (or: uv sync --extra dashboard)"
        )


def streamlit_available() -> bool:
    return importlib.util.find_spec("streamlit") is not None


def app_path() -> Path:
    return Path(__file__).with_name("app.py")


def build_command(*, port: int = 8501, headless: bool = False) -> list[str]:
    """The argv used to launch Streamlit (exposed for testing)."""
    cmd = [
        sys.executable,
        "-m",
        "streamlit",
        "run",
        str(app_path()),
        "--server.port",
        str(port),
    ]
    if headless:
        cmd += ["--server.headless", "true"]
    return cmd


def _credentials_path() -> Path:
    return Path.home() / ".streamlit" / "credentials.toml"


def suppress_first_run_prompt(path: Path | None = None) -> None:
    """Skip Streamlit's first-run email prompt so ``asfops dashboard`` never hangs.

    On first launch Streamlit blocks on an interactive "enter your email" prompt;
    with no TTY that stalls the server. We write the same empty-email credentials
    file Streamlit itself writes after the prompt — but only when the user has
    none, so an existing Streamlit setup is never touched.
    """
    creds = path or _credentials_path()
    if creds.exists():
        return
    creds.parent.mkdir(parents=True, exist_ok=True)
    creds.write_text('[general]\nemail = ""\n', encoding="utf-8")


def launch(*, port: int = 8501, headless: bool = False) -> int:
    """Run the Streamlit dashboard; blocks until the server exits."""
    if not streamlit_available():
        raise DashboardNotInstalledError
    suppress_first_run_prompt()
    return subprocess.call(build_command(port=port, headless=headless))


__all__ = [
    "DashboardNotInstalledError",
    "app_path",
    "build_command",
    "launch",
    "streamlit_available",
    "suppress_first_run_prompt",
]
