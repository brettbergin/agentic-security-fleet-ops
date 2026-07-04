"""Exception hierarchy for asfops."""

from __future__ import annotations


class AsfopsError(Exception):
    """Base class for all asfops errors."""


class CopilotRuntimeError(AsfopsError):
    """The Copilot runtime failed to start, respond, or complete a turn."""


class ToolsNotSupportedError(AsfopsError):
    """Raised when pydantic-ai function tools are requested on a CopilotModel.

    The Copilot runtime executes tools inside its own turn and cannot return
    tool calls to pydantic-ai. Use an API-key model (e.g. ``openai:...`` or
    ``anthropic:...``) for agents that need custom tools.
    """


class RoleNotFoundError(AsfopsError):
    """Raised when a role slug is not present in the registry."""

    def __init__(self, slug: str, known: tuple[str, ...]) -> None:
        self.slug = slug
        self.known = known
        super().__init__(f"Unknown role slug {slug!r}. Known roles: {', '.join(known)}")


class TriageError(AsfopsError):
    """Raised when triage produces no usable role selection."""
