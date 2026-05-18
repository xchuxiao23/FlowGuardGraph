from pathlib import Path

import pandas as pd

from flowguardgraph.report_generator import (
    generate_html_report,
    generate_markdown_report,
)


def _sample_summaries() -> dict:
    return {
        "compliance": {"total_events": 3, "violation_events": 2},
        "risk": {"high_risk_events": 1, "external_events": 2},
        "ml": {"ml_anomaly_events": 1},
        "delta": {"num_delta_edges": 2},
    }


def _sample_risk_dataframe() -> pd.DataFrame:
    return pd.DataFrame(
        [
            {
                "timestamp": "2026-05-18T09:00:00Z",
                "source": "internal_db.user_profile",
                "target": "external_partner",
                "field": "id_card",
                "violation_type": "external_unapproved",
                "risk_score": 0.84,
                "hybrid_risk_score": 0.88,
                "risk_level": "high",
                "hybrid_risk_level": "high",
                "is_allowed": False,
            },
            {
                "timestamp": "2026-05-18T09:00:07Z",
                "source": "internal_db.user_profile",
                "target": "analytics_service",
                "field": "name",
                "violation_type": "none",
                "risk_score": 0.06,
                "hybrid_risk_score": 0.08,
                "risk_level": "low",
                "hybrid_risk_level": "low",
                "is_allowed": True,
            },
        ]
    )


def test_generate_markdown_report(tmp_path):
    report_path = generate_markdown_report(
        dataset_name="demo_test",
        summaries=_sample_summaries(),
        risk_dataframe=_sample_risk_dataframe(),
        output_dir=str(tmp_path),
        detection_time="2026-05-18 10:00:00",
    )

    content = Path(report_path).read_text(encoding="utf-8")
    assert Path(report_path).exists()
    assert "FlowGuardGraph" in content
    assert "总事件数" in content
    assert "违规事件数" in content
    assert "高风险事件数" in content


def test_generate_html_report(tmp_path):
    report_path = generate_html_report(
        dataset_name="demo_test",
        summaries=_sample_summaries(),
        risk_dataframe=_sample_risk_dataframe(),
        output_dir=str(tmp_path),
        detection_time="2026-05-18 10:00:00",
    )

    content = Path(report_path).read_text(encoding="utf-8")
    assert Path(report_path).exists()
    assert "<html" in content
    assert "FlowGuardGraph" in content
