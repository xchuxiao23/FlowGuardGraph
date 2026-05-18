from pathlib import Path
from typing import Any

import pandas as pd
from pydantic import BaseModel
from sklearn.ensemble import IsolationForest

from flowguardgraph.compliance_checker import ComplianceResult, check_compliance
from flowguardgraph.log_parser import FlowEvent, load_flow_logs
from flowguardgraph.policy_loader import load_policy
from flowguardgraph.risk_analyzer import (
    RiskResult,
    analyze_risks,
    load_sensitive_fields,
)


class MLAnomalyResult(BaseModel):
    risk_result: RiskResult
    features: dict[str, float | int]
    ml_anomaly_score: float
    ml_is_anomaly: bool
    hybrid_risk_score: float
    hybrid_risk_level: str
    ml_reason: str


def extract_ml_features(risk_result: RiskResult) -> dict[str, float | int]:
    compliance_result: ComplianceResult = risk_result.compliance_result
    event: FlowEvent = compliance_result.event
    normalized_target = event.target.lower()

    return {
        "volume": int(event.volume),
        "is_external_target": int(risk_result.external_target),
        "policy_violation": int(risk_result.policy_violation),
        "purpose_mismatch": int(risk_result.purpose_mismatch),
        "sensitivity_score": float(risk_result.sensitivity_score),
        "is_high_sensitivity": int(
            risk_result.sensitivity_level in {"high", "critical"}
        ),
        "is_critical_sensitivity": int(risk_result.sensitivity_level == "critical"),
        "target_is_unknown": int("unknown" in normalized_target),
        "target_is_partner": int("partner" in normalized_target),
        "target_is_crm": int("crm" in normalized_target),
        "risk_score": float(risk_result.risk_score),
    }


def build_feature_dataframe(risk_results: list[RiskResult]) -> pd.DataFrame:
    dataframe = pd.DataFrame(
        [extract_ml_features(risk_result) for risk_result in risk_results]
    )
    if dataframe.empty:
        return dataframe

    dataframe = dataframe.apply(pd.to_numeric, errors="coerce").fillna(0)
    return dataframe


def run_isolation_forest(
    risk_results: list[RiskResult],
    contamination: float = 0.15,
    random_state: int = 42,
) -> list[MLAnomalyResult]:
    if not risk_results:
        return []

    features = build_feature_dataframe(risk_results)
    model = IsolationForest(
        contamination=contamination,
        random_state=random_state,
    )
    predictions = model.fit_predict(features)
    raw_anomaly_scores = -model.decision_function(features)
    normalized_scores = _normalize_scores(raw_anomaly_scores)

    results: list[MLAnomalyResult] = []
    for risk_result, feature_row, prediction, ml_score in zip(
        risk_results,
        features.to_dict("records"),
        predictions,
        normalized_scores,
        strict=True,
    ):
        ml_is_anomaly = int(prediction) == -1
        hybrid_risk_score = round(
            (0.75 * risk_result.risk_score) + (0.25 * float(ml_score)),
            4,
        )
        results.append(
            MLAnomalyResult(
                risk_result=risk_result,
                features=feature_row,
                ml_anomaly_score=round(float(ml_score), 4),
                ml_is_anomaly=ml_is_anomaly,
                hybrid_risk_score=hybrid_risk_score,
                hybrid_risk_level=_classify_hybrid_risk_level(hybrid_risk_score),
                ml_reason=_build_ml_reason(ml_is_anomaly),
            )
        )

    return results


def summarize_ml_results(ml_results: list[MLAnomalyResult]) -> dict[str, int | float]:
    total_events = len(ml_results)
    average_ml_score = (
        sum(result.ml_anomaly_score for result in ml_results) / total_events
        if total_events
        else 0.0
    )
    max_ml_score = (
        max(result.ml_anomaly_score for result in ml_results) if ml_results else 0.0
    )

    return {
        "total_events": total_events,
        "ml_anomaly_events": sum(
            1 for result in ml_results if result.ml_is_anomaly
        ),
        "average_ml_anomaly_score": round(average_ml_score, 4),
        "max_ml_anomaly_score": round(max_ml_score, 4),
        "high_hybrid_risk_events": sum(
            1 for result in ml_results if result.hybrid_risk_level == "high"
        ),
        "medium_hybrid_risk_events": sum(
            1 for result in ml_results if result.hybrid_risk_level == "medium"
        ),
        "low_hybrid_risk_events": sum(
            1 for result in ml_results if result.hybrid_risk_level == "low"
        ),
    }


def _normalize_scores(raw_scores: Any) -> list[float]:
    scores = [float(score) for score in raw_scores]
    if not scores:
        return []

    min_score = min(scores)
    max_score = max(scores)
    if max_score == min_score:
        return [0.0 for _ in scores]

    return [
        (score - min_score) / (max_score - min_score)
        for score in scores
    ]


def _classify_hybrid_risk_level(hybrid_risk_score: float) -> str:
    if hybrid_risk_score >= 0.75:
        return "high"
    if hybrid_risk_score >= 0.45:
        return "medium"
    return "low"


def _build_ml_reason(ml_is_anomaly: bool) -> str:
    if ml_is_anomaly:
        return "机器学习模型认为该数据流行为在当前样本中具有异常特征，建议重点关注。"
    return "机器学习模型未将该数据流判定为异常。"


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
    ml_results = run_isolation_forest(risk_results)
    summary = summarize_ml_results(ml_results)

    print(f"total_events: {summary['total_events']}")
    print(f"ml_anomaly_events: {summary['ml_anomaly_events']}")
    print(f"average_ml_anomaly_score: {summary['average_ml_anomaly_score']}")
    print(f"max_ml_anomaly_score: {summary['max_ml_anomaly_score']}")
    print(f"high_hybrid_risk_events: {summary['high_hybrid_risk_events']}")
    print("top_5_ml_anomaly_events:")
    for result in sorted(
        ml_results,
        key=lambda item: item.ml_anomaly_score,
        reverse=True,
    )[:5]:
        event = result.risk_result.compliance_result.event
        print(
            "  "
            f"source={event.source}, "
            f"target={event.target}, "
            f"field={event.field}, "
            f"ml_anomaly_score={result.ml_anomaly_score}, "
            f"hybrid_risk_score={result.hybrid_risk_score}, "
            f"hybrid_risk_level={result.hybrid_risk_level}"
        )


if __name__ == "__main__":
    main()
