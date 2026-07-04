"""Model providers and resolution for asfops."""

from asfops.models.bridge import BridgeResult, CopilotBridge
from asfops.models.client import get_shared_client, shutdown
from asfops.models.copilot import DEFAULT_COPILOT_MODEL, CopilotModel, CopilotStreamedResponse
from asfops.models.resolve import ModelRef, resolve_model

__all__ = [
    "DEFAULT_COPILOT_MODEL",
    "BridgeResult",
    "CopilotBridge",
    "CopilotModel",
    "CopilotStreamedResponse",
    "ModelRef",
    "get_shared_client",
    "resolve_model",
    "shutdown",
]
