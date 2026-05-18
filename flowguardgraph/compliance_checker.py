from pathlib import Path
from typing import Any

from pydantic import BaseModel

from flowguardgraph.log_parser import (
    FlowEvent,
    infer_external_target,
    load_flow_logs,
)
from flowguardgraph.policy_loader import (
    PolicyConfig,
    build_allowed_flow_index,
    get_allowed_policy,
    load_policy,
)


class ComplianceResult(BaseModel):
    event: FlowEvent
    is_allowed: bool
    violation_type: str
    reason: str
    expected_purpose: str | None = None
    actual_purpose: str | None = None


def check_event_compliance(
    event: FlowEvent,
    allowed_index: dict[tuple[str, str, str], dict[str, Any]],
) -> ComplianceResult:
    allowed_policy = get_allowed_policy(
        event.source,
        event.target,
        event.field,
        allowed_index,
    )

    if allowed_policy is None:
        violation_type = (
            "external_unapproved"
            if infer_external_target(event.target)
            else "unregistered_flow"
        )
        return ComplianceResult(
            event=event,
            is_allowed=False,
            violation_type=violation_type,
            reason=(
                f"实际传输字段 {event.field} 未在声明规则中允许从 "
                f"{event.source} 传输到 {event.target}。"
            ),
        )

    expected_purpose = allowed_policy["purpose"]
    if event.purpose != expected_purpose:
        return ComplianceResult(
            event=event,
            is_allowed=False,
            violation_type="purpose_mismatch",
            reason=(
                f"字段 {event.field} 从 {event.source} 传输到 {event.target} "
                f"的声明用途为 {expected_purpose}，但实际用途为 {event.purpose}。"
            ),
            expected_purpose=expected_purpose,
            actual_purpose=event.purpose,
        )

    return ComplianceResult(
        event=event,
        is_allowed=True,
        violation_type="none",
        reason="该数据流符合声明规则。",
        expected_purpose=expected_purpose,
        actual_purpose=event.purpose,
    )


def check_compliance(
    events: list[FlowEvent],
    policy: PolicyConfig,
) -> list[ComplianceResult]:
    allowed_index = build_allowed_flow_index(policy)
    return [check_event_compliance(event, allowed_index) for event in events]


def summarize_compliance_results(
    results: list[ComplianceResult],
) -> dict[str, int | float]:
    total_events = len(results)
    allowed_events = sum(1 for result in results if result.is_allowed)
    violation_events = total_events - allowed_events

    return {
        "total_events": total_events,
        "allowed_events": allowed_events,
        "violation_events": violation_events,
        "external_unapproved": sum(
            1 for result in results if result.violation_type == "external_unapproved"
        ),
        "unregistered_flow": sum(
            1 for result in results if result.violation_type == "unregistered_flow"
        ),
        "purpose_mismatch": sum(
            1 for result in results if result.violation_type == "purpose_mismatch"
        ),
        "violation_rate": violation_events / total_events if total_events else 0.0,
    }


def main() -> None:
    project_root = Path(__file__).resolve().parents[1]
    policy_path = project_root / "examples" / "policy_declaration.yaml"
    log_path = project_root / "examples" / "actual_flow_logs.csv"

    policy = load_policy(str(policy_path))
    events = load_flow_logs(str(log_path))
    results = check_compliance(events, policy)
    summary = summarize_compliance_results(results)

    print(f"total_events: {summary['total_events']}")
    print(f"allowed_events: {summary['allowed_events']}")
    print(f"violation_events: {summary['violation_events']}")
    print(f"external_unapproved: {summary['external_unapproved']}")
    print(f"unregistered_flow: {summary['unregistered_flow']}")
    print(f"purpose_mismatch: {summary['purpose_mismatch']}")
    print("first_5_violation_reasons:")
    for result in [result for result in results if not result.is_allowed][:5]:
        print(f"  {result.reason}")


if __name__ == "__main__":
    main()
