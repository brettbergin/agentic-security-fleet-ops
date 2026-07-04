from __future__ import annotations

from typing import Any

import pytest

import asfops.models.client as client_mod
from asfops.exceptions import CopilotRuntimeError


@pytest.fixture(autouse=True)
def _reset_client() -> Any:
    client_mod._client = None
    yield
    client_mod._client = None


async def test_shutdown_when_no_client() -> None:
    # Should be a no-op, not an error.
    await client_mod.shutdown()
    assert client_mod._client is None


async def test_get_shared_client_wraps_start_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    import copilot

    class BrokenClient:
        def __init__(self, **kw: Any) -> None: ...

        async def start(self) -> None:
            raise RuntimeError("no auth")

    monkeypatch.setattr(copilot, "CopilotClient", BrokenClient)
    with pytest.raises(CopilotRuntimeError, match="Copilot runtime"):
        await client_mod.get_shared_client()
    assert client_mod._client is None


async def test_get_shared_client_caches_and_shuts_down(monkeypatch: pytest.MonkeyPatch) -> None:
    import copilot

    events: list[str] = []

    class OkClient:
        def __init__(self, **kw: Any) -> None: ...

        async def start(self) -> None:
            events.append("start")

        async def stop(self) -> None:
            events.append("stop")

    monkeypatch.setattr(copilot, "CopilotClient", OkClient)
    c1 = await client_mod.get_shared_client()
    c2 = await client_mod.get_shared_client()
    assert c1 is c2  # cached singleton
    assert events == ["start"]  # started once
    await client_mod.shutdown()
    assert events == ["start", "stop"]
    assert client_mod._client is None
