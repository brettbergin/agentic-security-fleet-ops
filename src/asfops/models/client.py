"""Shared lifecycle management for the Copilot CLI runtime client.

Starting the Copilot runtime spawns a CLI subprocess, which is far too slow to
do per model request. A single process-wide client is shared by every
:class:`~asfops.models.copilot.CopilotModel`; each request gets its own
session on that client.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

from asfops.exceptions import CopilotRuntimeError
from asfops.logs import get_logger

if TYPE_CHECKING:
    from copilot import CopilotClient

log = get_logger("copilot.client")

_lock = asyncio.Lock()
_client: CopilotClient | None = None


async def get_shared_client() -> CopilotClient:
    """Return the process-wide Copilot client, starting it on first use."""
    global _client
    async with _lock:
        if _client is None:
            from copilot import CopilotClient

            log.info("copilot_client_starting")
            client = CopilotClient(log_level="error")
            try:
                await client.start()
            except Exception as exc:
                log.error("copilot_client_start_failed", error=str(exc), exc_info=exc)
                raise CopilotRuntimeError(
                    "Failed to start the GitHub Copilot runtime. Check that you are "
                    "authenticated (gh auth login, or COPILOT_GITHUB_TOKEN/GH_TOKEN/"
                    "GITHUB_TOKEN) and have a Copilot subscription."
                ) from exc
            _client = client
            log.info("copilot_client_started")
    return _client


async def shutdown() -> None:
    """Stop the shared Copilot client, if it was started.

    Shutdown is best-effort: a runtime that fails to stop cleanly (e.g. because
    the event loop is already tearing down) must not turn a completed
    assessment into a crash.
    """
    global _client
    async with _lock:
        if _client is not None:
            try:
                await _client.stop()
                log.info("copilot_client_stopped")
            except Exception:
                pass
            finally:
                _client = None
