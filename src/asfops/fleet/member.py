"""Build a pydantic-ai agent for a fleet member."""

from __future__ import annotations

from pydantic_ai import Agent
from pydantic_ai.models import Model

from asfops.fleet.roles import RoleSpec
from asfops.fleet.schemas import AgentReport


def build_agent(role: RoleSpec, model: Model, *, retries: int = 2) -> Agent[None, AgentReport]:
    """Create the agent that runs a single security-department role."""
    return Agent(
        model=model,
        output_type=role.output_schema,
        system_prompt=role.system_prompt,
        retries=retries,
        name=role.slug,
    )
