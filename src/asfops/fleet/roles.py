"""Role definitions and the fleet registry."""

from __future__ import annotations

from dataclasses import dataclass, field

from asfops.exceptions import RoleNotFoundError
from asfops.fleet.schemas import AgentReport


@dataclass(frozen=True, slots=True)
class RoleSpec:
    """A fleet member: one security-department role."""

    slug: str
    name: str
    charter: str
    system_prompt: str
    tags: tuple[str, ...] = ()
    output_schema: type[AgentReport] = AgentReport
    default_model: str | None = None
    """Optional per-role model override (a model ref string)."""


@dataclass
class RoleRegistry:
    """Registry of every role available to the orchestrator."""

    _roles: dict[str, RoleSpec] = field(default_factory=dict)

    def register(self, spec: RoleSpec) -> RoleSpec:
        if spec.slug in self._roles:
            raise ValueError(f"Role slug {spec.slug!r} is already registered.")
        self._roles[spec.slug] = spec
        return spec

    def get(self, slug: str) -> RoleSpec:
        try:
            return self._roles[slug]
        except KeyError:
            raise RoleNotFoundError(slug, self.slugs()) from None

    def all(self) -> tuple[RoleSpec, ...]:
        return tuple(self._roles.values())

    def slugs(self) -> tuple[str, ...]:
        return tuple(self._roles)

    def __contains__(self, slug: str) -> bool:
        return slug in self._roles

    def __len__(self) -> int:
        return len(self._roles)


REGISTRY = RoleRegistry()
"""The default fleet registry, populated by :mod:`asfops.fleet.roster` at import."""
