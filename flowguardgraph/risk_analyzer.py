import json
from pathlib import Path

from pydantic import BaseModel

from flowguardgraph.compliance_checker import (
    ComplianceResult,
    check_compliance,
)
from flowguardgraph.log_parser import (
    infer_external_target,
    load_flow_logs,
)
from flowguardgraph.policy_loader import load_policy


SENSITIVITY_SCORES = {
    "low": 0.2,
    "medium": 0.5,
    "high": 0.8,
    "critical": 1.0,
    "unknown": 0.1,
}


class RiskResult(BaseModel):
    compliance_result: ComplianceResult
    sensitivity_level: str
    sensitivity_score: float
    external_target: bool
    policy_violation: bool
    purpose_mismatch: bool
    risk_score: float
    risk_level: str
    risk_reason: str


def load_sensitive_fields(path: str) -> dict[str, str]:
    sensitive_path = Path(path)
    if not sensitive_path.exists():
        raise FileNotFoundError(f"Sensitive fields file not found: {sensitive_path}")

    try:
        with sensitive_path.open("r", encoding="utf-8") as file:
            sensitive_map = json.load(file)
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"Invalid JSON in sensitive fields file {sensitive_path}: {exc}"
        ) from exc

    if not isinstance(sensitive_map, dict):
        raise ValueError(
            f"Invalid sensitive fields schema in {sensitive_path}: expected object"
        )

    return {str(field): str(level) for field, level in sensitive_map.items()}


def get_sensitivity(
    field: str,
    sensitive_map: dict[str, str],
) -> tuple[str, float]:
    normalized_field = field.lower()
    normalized_map = {
        sensitive_field.lower(): level.lower()
        for sensitive_field, level in sensitive_map.items()
    }
    sensitivity_level = normalized_map.get(normalized_field, "unknown")
    sensitivity_score = SENSITIVITY_SCORES.get(sensitivity_level, 0.1)
    if sensitivity_level not in SENSITIVITY_SCORES:
        sensitivity_level = "unknown"

    return sensitivity_level, sensitivity_score


def compute_risk_score(
    compliance_result: ComplianceResult,
    sensitive_map: dict[str, str],
) -> RiskResult:
    event = compliance_result.event
    sensitivity_level, sensitivity_score = get_sensitivity(
        event.field,
        sensitive_map,
    )
    external_target = infer_external_target(event.target)
    policy_violation = not compliance_result.is_allowed
    purpose_mismatch = compliance_result.violation_type == "purpose_mismatch"

    risk_score = round(
        (0.4 * int(policy_violation))
        + (0.3 * sensitivity_score)
        + (0.2 * int(external_target))
        + (0.1 * int(purpose_mismatch)),
        4,
    )
    risk_level = _classify_risk_level(risk_score)
    risk_reason = _build_risk_reason(
        field=event.field,
        sensitivity_level=sensitivity_level,
        external_target=external_target,
        policy_violation=policy_violation,
        purpose_mismatch=purpose_mismatch,
        risk_level=risk_level,
    )

    return RiskResult(
        compliance_result=compliance_result,
        sensitivity_level=sensitivity_level,
        sensitivity_score=sensitivity_score,
        external_target=external_target,
        policy_violation=policy_violation,
        purpose_mismatch=purpose_mismatch,
        risk_score=risk_score,
        risk_level=risk_level,
        risk_reason=risk_reason,
    )


def analyze_risks(
    compliance_results: list[ComplianceResult],
    sensitive_map: dict[str, str],
) -> list[RiskResult]:
    return [
        compute_risk_score(compliance_result, sensitive_map)
        for compliance_result in compliance_results
    ]


def summarize_risk_results(
    risk_results: list[RiskResult],
) -> dict[str, int | float]:
    total_events = len(risk_results)
    average_risk_score = (
        sum(result.risk_score for result in risk_results) / total_events
        if total_events
        else 0.0
    )
    max_risk_score = (
        max(result.risk_score for result in risk_results) if risk_results else 0.0
    )

    return {
        "total_events": total_events,
        "high_risk_events": sum(
            1 for result in risk_results if result.risk_level == "high"
        ),
        "medium_risk_events": sum(
            1 for result in risk_results if result.risk_level == "medium"
        ),
        "low_risk_events": sum(
            1 for result in risk_results if result.risk_level == "low"
        ),
        "external_events": sum(1 for result in risk_results if result.external_target),
        "policy_violation_events": sum(
            1 for result in risk_results if result.policy_violation
        ),
        "average_risk_score": round(average_risk_score, 4),
        "max_risk_score": round(max_risk_score, 4),
    }


def _classify_risk_level(risk_score: float) -> str:
    if risk_score >= 0.75:
        return "high"
    if risk_score >= 0.45:
        return "medium"
    return "low"


def _build_risk_reason(
    field: str,
    sensitivity_level: str,
    external_target: bool,
    policy_violation: bool,
    purpose_mismatch: bool,
    risk_level: str,
) -> str:
    if risk_level == "high":
        if policy_violation and external_target:
            risk_factor = "且发生未授权外部传输"
        elif policy_violation:
            risk_factor = "且存在未声明或声明不一致风险"
        elif external_target:
            risk_factor = "且发生外部传输"
        else:
            risk_factor = "且存在高敏感字段访问风险"
        return (
            f"字段 {field} 属于 {sensitivity_level} 敏感字段，"
            f"{risk_factor}，风险等级为 high。"
        )

    if risk_level == "medium":
        if purpose_mismatch:
            risk_factor = "存在声明用途不一致风险"
        else:
            risk_factor = "存在外部传输或声明不一致风险"
        return (
            f"字段 {field} 属于 {sensitivity_level} 敏感字段，"
            f"{risk_factor}，风险等级为 medium。"
        )

    return "该数据流风险较低。"


def main() -> None:
    project_root = Path(__file__).resolve().parents[1]
    policy_path = project_root / "examples" / "policy_declaration.yaml"
    log_path = project_root / "examples" / "actual_flow_logs.csv"
    sensitive_path = project_root / "examples" / "sensitive_fields.json"

    policy = load_policy(str(policy_path))
    events = load_flow_logs(str(log_path))
    compliance_results = check_compliance(events, policy)
    sensitive_map = load_sensitive_fields(str(sensitive_path))
    risk_results = analyze_risks(compliance_results, sensitive_map)
    summary = summarize_risk_results(risk_results)

    print(f"total_events: {summary['total_events']}")
    print(f"high_risk_events: {summary['high_risk_events']}")
    print(f"medium_risk_events: {summary['medium_risk_events']}")
    print(f"low_risk_events: {summary['low_risk_events']}")
    print(f"external_events: {summary['external_events']}")
    print(f"average_risk_score: {summary['average_risk_score']}")
    print(f"max_risk_score: {summary['max_risk_score']}")
    print("top_5_high_risk_events:")
    high_risk_results = sorted(
        [result for result in risk_results if result.risk_level == "high"],
        key=lambda result: result.risk_score,
        reverse=True,
    )
    for result in high_risk_results[:5]:
        event = result.compliance_result.event
        print(
            "  "
            f"source={event.source}, "
            f"target={event.target}, "
            f"field={event.field}, "
            f"risk_score={result.risk_score}, "
            f"risk_level={result.risk_level}, "
            f"risk_reason={result.risk_reason}"
        )


if __name__ == "__main__":
    main()
