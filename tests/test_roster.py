import pytest
from pydantic_ai.models.test import TestModel

from asfops.exceptions import RoleNotFoundError
from asfops.fleet.member import build_agent
from asfops.fleet.roles import REGISTRY, RoleRegistry, RoleSpec
from asfops.fleet.roster import _ROLES
from asfops.fleet.schemas import AgentReport

EXPECTED_SLUGS = {
    "product-security",
    "security-architect",
    "threat-model",
    "appsec",
    "cloudsec",
    "iam",
    "pentest",
    "red-team",
    "bug-bounty",
    "vuln-mgmt",
    "supply-chain",
    "threat-detection",
    "soc-analyst",
    "incident-response",
    "grc",
    "privacy",
    "ciso",
}


def test_full_department_registered() -> None:
    assert set(REGISTRY.slugs()) == EXPECTED_SLUGS
    assert len(REGISTRY) == len(EXPECTED_SLUGS) == 17


def test_slugs_unique() -> None:
    slugs = [r.slug for r in _ROLES]
    assert len(slugs) == len(set(slugs))


@pytest.mark.parametrize("role", _ROLES, ids=lambda r: r.slug)
def test_role_prompts_are_substantial(role: RoleSpec) -> None:
    assert role.name
    assert role.charter
    assert len(role.system_prompt) > 200
    assert role.tags
    assert issubclass(role.output_schema, AgentReport)


def test_get_unknown_role_raises() -> None:
    with pytest.raises(RoleNotFoundError):
        REGISTRY.get("does-not-exist")


def test_duplicate_registration_rejected() -> None:
    reg = RoleRegistry()
    spec = RoleSpec(slug="x", name="X", charter="c", system_prompt="p" * 300, tags=("t",))
    reg.register(spec)
    with pytest.raises(ValueError, match="already registered"):
        reg.register(spec)


async def test_build_agent_runs_with_test_model() -> None:
    role = REGISTRY.get("appsec")
    agent = build_agent(role, TestModel())
    result = await agent.run("Review this endpoint")
    assert isinstance(result.output, AgentReport)
