from pathlib import Path

from flowguardgraph.compliance_checker import check_compliance, check_event_compliance
from flowguardgraph.log_parser import FlowEvent, load_flow_logs
from flowguardgraph.policy_loader import build_allowed_flow_index, load_policy
from flowguardgraph.risk_analyzer import (
    analyze_risks,
    compute_risk_score,
    get_sensitivity,
    load_sensitive_fields,
    summarize_risk_results,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = PROJECT_ROOT / "examples" / "policy_declaration.yaml"
LOG_PATH = PROJECT_ROOT / "examples" / "actual_flow_logs.csv"
SENSITIVE_PATH = PROJECT_ROOT / "examples" / "sensitive_fields.json"


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


def test_load_sensitive_fields() -> None:
    sensitive_map = load_sensitive_fields(str(SENSITIVE_PATH))

    assert sensitive_map["id_card"] == "high"
    assert sensitive_map["password"] == "critical"


def test_get_sensitivity() -> None:
    sensitive_map = load_sensitive_fields(str(SENSITIVE_PATH))

    assert get_sensitivity("name", sensitive_map) == ("low", 0.2)
    assert get_sensitivity("id_card", sensitive_map) == ("high", 0.8)
    assert get_sensitivity("unknown_field", sensitive_map) == ("unknown", 0.1)


def test_high_risk_external_sensitive_violation() -> None:
    policy = load_policy(str(POLICY_PATH))
    allowed_index = build_allowed_flow_index(policy)
    sensitive_map = load_sensitive_fields(str(SENSITIVE_PATH))
    event = make_flow_event(
        source="internal_db.user_profile",
        target="external_partner",
        field="id_card",
        purpose="unknown",
    )

    compliance_result = check_event_compliance(event, allowed_index)
    risk_result = compute_risk_score(compliance_result, sensitive_map)

    assert risk_result.risk_level == "high"
    assert risk_result.risk_score >= 0.75


def test_low_risk_allowed_internal_flow() -> None:
    policy = load_policy(str(POLICY_PATH))
    allowed_index = build_allowed_flow_index(policy)
    sensitive_map = load_sensitive_fields(str(SENSITIVE_PATH))
    event = make_flow_event(
        source="internal_db.user_profile",
        target="analytics_service",
        field="name",
        purpose="statistics",
    )

    compliance_result = check_event_compliance(event, allowed_index)
    risk_result = compute_risk_score(compliance_result, sensitive_map)

    assert risk_result.risk_level == "low"
    assert risk_result.risk_score < 0.45


def test_analyze_risks_summary() -> None:
    policy = load_policy(str(POLICY_PATH))
    events = load_flow_logs(str(LOG_PATH))
    compliance_results = check_compliance(events, policy)
    sensitive_map = load_sensitive_fields(str(SENSITIVE_PATH))
    risk_results = analyze_risks(compliance_results, sensitive_map)
    summary = summarize_risk_results(risk_results)

    assert summary["total_events"] == 35
    assert summary["high_risk_events"] > 0
    assert summary["average_risk_score"] >= 0
    assert summary["max_risk_score"] <= 1.0
