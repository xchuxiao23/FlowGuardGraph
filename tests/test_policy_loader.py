from pathlib import Path

from flowguardgraph.policy_loader import (
    build_allowed_flow_index,
    get_allowed_policy,
    load_policy,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = PROJECT_ROOT / "examples" / "policy_declaration.yaml"


def test_load_policy_success() -> None:
    policy = load_policy(str(POLICY_PATH))

    assert len(policy.systems) > 0
    assert len(policy.allowed_flows) > 0


def test_build_allowed_flow_index() -> None:
    policy = load_policy(str(POLICY_PATH))
    allowed_index = build_allowed_flow_index(policy)

    assert isinstance(allowed_index, dict)
    assert len(allowed_index) > len(policy.allowed_flows)

    rule = allowed_index[
        ("internal_db.user_profile", "analytics_service", "name")
    ]
    assert rule["purpose"] == "statistics"


def test_external_allowed_policy() -> None:
    policy = load_policy(str(POLICY_PATH))
    allowed_index = build_allowed_flow_index(policy)

    rule = get_allowed_policy(
        "internal_db.user_profile",
        "external_crm",
        "email",
        allowed_index,
    )

    assert rule is not None
    assert rule["allow_external"] is True


def test_get_allowed_policy_missing() -> None:
    policy = load_policy(str(POLICY_PATH))
    allowed_index = build_allowed_flow_index(policy)

    rule = get_allowed_policy(
        "internal_db.user_profile",
        "external_crm",
        "phone",
        allowed_index,
    )

    assert rule is None
