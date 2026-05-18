from pathlib import Path

from flowguardgraph.compliance_checker import (
    check_compliance,
    check_event_compliance,
    summarize_compliance_results,
)
from flowguardgraph.log_parser import FlowEvent, load_flow_logs
from flowguardgraph.policy_loader import build_allowed_flow_index, load_policy


PROJECT_ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = PROJECT_ROOT / "examples" / "policy_declaration.yaml"
LOG_PATH = PROJECT_ROOT / "examples" / "actual_flow_logs.csv"


def make_flow_event(
    source: str,
    target: str,
    field: str,
    purpose: str,
) -> FlowEvent:
    return FlowEvent(
        timestamp="2026-05-18T12:00:00Z",
        user="test_user",
        source=source,
        target=target,
        field=field,
        action="transfer",
        purpose=purpose,
        volume=1,
    )


def test_check_compliance_summary() -> None:
    policy = load_policy(str(POLICY_PATH))
    events = load_flow_logs(str(LOG_PATH))
    results = check_compliance(events, policy)
    summary = summarize_compliance_results(results)

    assert len(results) == 35
    assert summary["violation_events"] > 0
    assert summary["allowed_events"] > 0


def test_allowed_flow() -> None:
    policy = load_policy(str(POLICY_PATH))
    allowed_index = build_allowed_flow_index(policy)
    event = make_flow_event(
        source="internal_db.user_profile",
        target="analytics_service",
        field="name",
        purpose="statistics",
    )

    result = check_event_compliance(event, allowed_index)

    assert result.is_allowed is True
    assert result.violation_type == "none"


def test_unregistered_internal_or_external_flow() -> None:
    policy = load_policy(str(POLICY_PATH))
    allowed_index = build_allowed_flow_index(policy)
    event = make_flow_event(
        source="internal_db.user_profile",
        target="external_crm",
        field="phone",
        purpose="customer_service",
    )

    result = check_event_compliance(event, allowed_index)

    assert result.is_allowed is False
    assert result.violation_type == "external_unapproved"


def test_purpose_mismatch() -> None:
    policy = load_policy(str(POLICY_PATH))
    allowed_index = build_allowed_flow_index(policy)
    event = make_flow_event(
        source="internal_db.user_profile",
        target="analytics_service",
        field="name",
        purpose="marketing",
    )

    result = check_event_compliance(event, allowed_index)

    assert result.is_allowed is False
    assert result.violation_type == "purpose_mismatch"
    assert result.expected_purpose == "statistics"
    assert result.actual_purpose == "marketing"


def test_external_unapproved() -> None:
    policy = load_policy(str(POLICY_PATH))
    allowed_index = build_allowed_flow_index(policy)
    event = make_flow_event(
        source="internal_db.user_profile",
        target="external_partner",
        field="id_card",
        purpose="unknown",
    )

    result = check_event_compliance(event, allowed_index)

    assert result.is_allowed is False
    assert result.violation_type == "external_unapproved"
