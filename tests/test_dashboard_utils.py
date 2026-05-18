import pandas as pd

from flowguardgraph.dashboard_utils import (
    build_risk_heatmap_dataframe,
    build_risk_heatmap_detail_dataframe,
)


def _sample_risk_rows() -> pd.DataFrame:
    return pd.DataFrame(
        [
            {
                "source": "internal_db.user_profile",
                "target": "external_partner",
                "field": "id_card",
                "risk_score": 0.84,
                "risk_level": "high",
                "is_allowed": False,
                "violation_type": "external_unapproved",
            },
            {
                "source": "internal_db.user_profile",
                "target": "external_partner",
                "field": "phone",
                "risk_score": 0.75,
                "risk_level": "high",
                "is_allowed": False,
                "violation_type": "external_unapproved",
            },
            {
                "source": "internal_db.order_info",
                "target": "analytics_service",
                "field": "order_id",
                "risk_score": 0.06,
                "risk_level": "low",
                "is_allowed": True,
                "violation_type": "none",
            },
        ]
    )


def test_build_risk_heatmap_detail_dataframe() -> None:
    detail = build_risk_heatmap_detail_dataframe(_sample_risk_rows())

    assert not detail.empty
    assert {
        "source",
        "target",
        "avg_risk_score",
        "max_risk_score",
        "event_count",
        "violation_count",
        "high_risk_count",
        "fields",
        "violation_types",
    }.issubset(detail.columns)

    external_row = detail[
        (detail["source"] == "internal_db.user_profile")
        & (detail["target"] == "external_partner")
    ].iloc[0]
    assert external_row["event_count"] == 2
    assert external_row["violation_count"] == 2
    assert external_row["high_risk_count"] == 2
    assert external_row["max_risk_score"] == 0.84


def test_build_risk_heatmap_dataframe_default_metric() -> None:
    pivot = build_risk_heatmap_dataframe(_sample_risk_rows())

    assert not pivot.empty
    assert "internal_db.user_profile" in pivot.index
    assert "external_partner" in pivot.columns
    assert pivot.loc["internal_db.user_profile", "external_partner"] == 0.795


def test_build_risk_heatmap_dataframe_count_metric() -> None:
    pivot = build_risk_heatmap_dataframe(
        _sample_risk_rows(),
        metric="violation_count",
    )

    assert pivot.loc["internal_db.user_profile", "external_partner"] == 2
