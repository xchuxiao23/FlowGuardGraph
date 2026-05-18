from pathlib import Path

import pandas as pd

from flowguardgraph.compliance_checker import check_compliance
from flowguardgraph.log_parser import load_flow_logs
from flowguardgraph.ml_anomaly_detector import (
    build_feature_dataframe,
    extract_ml_features,
    run_isolation_forest,
    summarize_ml_results,
)
from flowguardgraph.policy_loader import load_policy
from flowguardgraph.risk_analyzer import analyze_risks, load_sensitive_fields


PROJECT_ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = PROJECT_ROOT / "examples" / "policy_declaration.yaml"
LOG_PATH = PROJECT_ROOT / "examples" / "actual_flow_logs.csv"
SENSITIVE_PATH = PROJECT_ROOT / "examples" / "sensitive_fields.json"


def build_example_risk_results():
    policy = load_policy(str(POLICY_PATH))
    events = load_flow_logs(str(LOG_PATH))
    compliance_results = check_compliance(events, policy)
    sensitive_map = load_sensitive_fields(str(SENSITIVE_PATH))
    return analyze_risks(compliance_results, sensitive_map)


def test_extract_ml_features() -> None:
    risk_results = build_example_risk_results()
    features = extract_ml_features(risk_results[0])

    assert isinstance(features, dict)
    assert "volume" in features
    assert "is_external_target" in features
    assert "policy_violation" in features
    assert "sensitivity_score" in features
    assert "risk_score" in features


def test_build_feature_dataframe() -> None:
    risk_results = build_example_risk_results()
    dataframe = build_feature_dataframe(risk_results)

    assert not dataframe.empty
    assert len(dataframe) == len(risk_results)
    assert all(
        pd.api.types.is_numeric_dtype(dataframe[column])
        for column in dataframe.columns
    )


def test_run_isolation_forest() -> None:
    risk_results = build_example_risk_results()
    ml_results = run_isolation_forest(risk_results)

    assert len(ml_results) == len(risk_results)
    assert all(hasattr(result, "ml_anomaly_score") for result in ml_results)
    assert all(0 <= result.ml_anomaly_score <= 1 for result in ml_results)
    assert all(0 <= result.hybrid_risk_score <= 1 for result in ml_results)


def test_summarize_ml_results() -> None:
    risk_results = build_example_risk_results()
    ml_results = run_isolation_forest(risk_results)
    summary = summarize_ml_results(ml_results)

    assert isinstance(summary, dict)
    assert summary["total_events"] == 35
    assert summary["max_ml_anomaly_score"] <= 1.0
    assert summary["high_hybrid_risk_events"] >= 0
