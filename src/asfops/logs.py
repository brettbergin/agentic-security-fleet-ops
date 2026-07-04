"""Dual logging subsystem for asfops.

Two distinct outputs per run, written under one per-run directory:

1. **Global application log** (``app.log``) — structlog JSON lines of
   application-wide lifecycle events, correlated by a fleet-level ``run_id``.
2. **Per-agent context logs** (``agents/<slug>.json``) — the *entire* context
   of each pydantic-ai agent invocation: full message history plus a metadata
   header (model, usage, duration, output).

Module named ``logs`` (not ``logging``) to avoid shadowing the stdlib.

Configuration is process-global (structlog) but the file handler and run
directory are per-:class:`RunLogger`, so concurrent-safe within one process
and cheap to tear down between runs.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any
from uuid import uuid4

import structlog

if TYPE_CHECKING:
    from pydantic import BaseModel
    from pydantic_ai.run import AgentRunResult

_LOGGER_NAMESPACE = "asfops"
_configured = False


@dataclass
class LoggingConfig:
    """Controls asfops logging for a fleet run.

    Logging is on by default but is automatically disabled while running under
    pytest (see :func:`_under_pytest`) unless ``force`` is set.
    """

    enabled: bool = True
    base_dir: Path = field(default_factory=lambda: Path("asfops-logs"))
    level: str = "INFO"
    agent_logs: bool = True
    console: bool = False
    force: bool = False
    """Force logging on even under pytest (used by the logging tests)."""


def _under_pytest() -> bool:
    return "PYTEST_CURRENT_TEST" in os.environ


def _effective_enabled(cfg: LoggingConfig) -> bool:
    if not cfg.enabled:
        return False
    if _under_pytest() and not cfg.force:
        return False
    return True


def get_logger(name: str | None = None) -> structlog.stdlib.BoundLogger:
    """Return a structlog logger under the ``asfops`` namespace.

    Safe to call at import time (before configuration): structlog returns a
    lazy proxy that binds to the active configuration on first use.
    """
    logger_name = _LOGGER_NAMESPACE if not name else f"{_LOGGER_NAMESPACE}.{name}"
    return structlog.get_logger(logger_name)  # type: ignore[no-any-return]


def ensure_configured(cfg: LoggingConfig | None = None) -> None:
    """Idempotently configure structlog's global processor chain.

    Only the shared processor pipeline is set here — the per-run file handler
    lives on :class:`RunLogger`, so this runs at most once per process.
    """
    global _configured
    if _configured:
        return
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.stdlib.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )
    _configured = True


def configure_logging(cfg: LoggingConfig | None = None) -> None:
    """Public convenience: set up asfops logging for library consumers."""
    ensure_configured(cfg)


def _new_run_id() -> str:
    return uuid4().hex


def _serialize_output(output: object) -> Any:
    if output is None:
        return None
    dump = getattr(output, "model_dump", None)
    if callable(dump):
        model_output: BaseModel = output  # type: ignore[assignment]
        return model_output.model_dump(mode="json")
    return output


class RunLogger:
    """Per-run logging handle: the global app log plus per-agent context logs.

    When logging is disabled (config off, or under pytest without ``force``)
    every method is a cheap no-op and no files are created.
    """

    def __init__(self, config: LoggingConfig, *, run_id: str | None = None) -> None:
        self.config = config
        self.run_id = run_id or _new_run_id()
        self.enabled = _effective_enabled(config)
        self.run_dir: Path | None = None
        self._handler: logging.Handler | None = None
        self._token: object | None = None

        if not self.enabled:
            self.log = get_logger("run")
            return

        ensure_configured(config)
        ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        self.run_dir = Path(config.base_dir) / f"{ts}-{self.run_id[:8]}"
        (self.run_dir / "agents").mkdir(parents=True, exist_ok=True)
        self._attach_handler(self.run_dir / "app.log")
        structlog.contextvars.bind_contextvars(run_id=self.run_id)
        self.log = get_logger("run")

    def _attach_handler(self, path: Path) -> None:
        handler = logging.FileHandler(path, encoding="utf-8")
        handler.setFormatter(
            structlog.stdlib.ProcessorFormatter(
                processor=structlog.processors.JSONRenderer(),
            )
        )
        root = logging.getLogger(_LOGGER_NAMESPACE)
        root.setLevel(self.config.level.upper())
        root.addHandler(handler)
        root.propagate = False
        self._handler = handler

    def agent_log(
        self,
        *,
        slug: str,
        role_name: str,
        model_id: str,
        run: AgentRunResult[Any] | None = None,
        duration_s: float,
        started_at: str | None = None,
        error: str | None = None,
    ) -> None:
        """Write one agent's entire context to ``agents/<slug>.json``."""
        if not self.enabled or not self.config.agent_logs or self.run_dir is None:
            return
        messages: Any = []
        output: Any = None
        agent_run_id: str | None = None
        usage: dict[str, Any] = {}
        if run is not None:
            messages = json.loads(bytes(run.all_messages_json()))
            output = _serialize_output(run.output)
            agent_run_id = str(run.run_id) if run.run_id is not None else None
            usage = _usage_dict(run.usage)
        record = {
            "slug": slug,
            "role_name": role_name,
            "model_id": model_id,
            "fleet_run_id": self.run_id,
            "agent_run_id": agent_run_id,
            "started_at": started_at,
            "duration_s": round(duration_s, 4),
            "usage": usage,
            "status": "failed" if error is not None else "ok",
            "error": error,
            "output": output,
            "messages": messages,
        }
        path = self.run_dir / "agents" / f"{slug}.json"
        path.write_text(json.dumps(record, indent=2, default=str), encoding="utf-8")

    def close(self) -> None:
        """Detach the file handler and clear the run's context vars."""
        if not self.enabled:
            return
        structlog.contextvars.unbind_contextvars("run_id")
        if self._handler is not None:
            logging.getLogger(_LOGGER_NAMESPACE).removeHandler(self._handler)
            self._handler.close()
            self._handler = None


def _usage_dict(usage: object) -> dict[str, Any]:
    fields = (
        "input_tokens",
        "output_tokens",
        "cache_read_tokens",
        "cache_write_tokens",
        "requests",
    )
    return {f: getattr(usage, f, None) for f in fields}


__all__ = [
    "LoggingConfig",
    "RunLogger",
    "configure_logging",
    "ensure_configured",
    "get_logger",
]
