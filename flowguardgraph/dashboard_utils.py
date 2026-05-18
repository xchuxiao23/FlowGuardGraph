import pandas as pd


HEATMAP_METRICS = [
    "avg_risk_score",
    "max_risk_score",
    "violation_count",
    "high_risk_count",
]


def build_risk_heatmap_dataframe(
    risk_rows: pd.DataFrame,
    top_sources: int = 15,
    top_targets: int = 15,
    metric: str = "avg_risk_score",
) -> pd.DataFrame:
    if metric not in HEATMAP_METRICS:
        raise ValueError(f"Unsupported heatmap metric: {metric}")

    detail = build_risk_heatmap_detail_dataframe(risk_rows)
    if detail.empty:
        return pd.DataFrame()

    top_source_names = _top_dimension_values(detail, "source", top_sources)
    top_target_names = _top_dimension_values(detail, "target", top_targets)
    filtered = detail[
        detail["source"].isin(top_source_names)
        & detail["target"].isin(top_target_names)
    ]

    pivot = (
        filtered.pivot_table(
            index="source",
            columns="target",
            values=metric,
            aggfunc="mean",
            fill_value=0,
        )
        .reindex(index=top_source_names, columns=top_target_names, fill_value=0)
        .fillna(0)
    )
    return pivot


def build_risk_heatmap_detail_dataframe(risk_rows: pd.DataFrame) -> pd.DataFrame:
    columns = [
        "source",
        "target",
        "avg_risk_score",
        "max_risk_score",
        "event_count",
        "violation_count",
        "high_risk_count",
        "fields",
        "violation_types",
    ]
    if risk_rows.empty:
        return pd.DataFrame(columns=columns)

    rows = risk_rows.copy()
    rows["violation_flag"] = _build_violation_flag(rows)
    rows["high_risk_flag"] = rows["risk_level"].eq("high").astype(int)

    detail = (
        rows.groupby(["source", "target"], as_index=False)
        .agg(
            avg_risk_score=("risk_score", "mean"),
            max_risk_score=("risk_score", "max"),
            event_count=("risk_score", "size"),
            violation_count=("violation_flag", "sum"),
            high_risk_count=("high_risk_flag", "sum"),
            fields=("field", _join_unique),
            violation_types=("violation_type", _join_unique),
        )
        .sort_values(
            by=["max_risk_score", "avg_risk_score", "event_count"],
            ascending=[False, False, False],
        )
        .reset_index(drop=True)
    )
    detail["avg_risk_score"] = detail["avg_risk_score"].round(4)
    detail["max_risk_score"] = detail["max_risk_score"].round(4)
    return detail[columns]


def _build_violation_flag(rows: pd.DataFrame) -> pd.Series:
    if "is_allowed" in rows.columns:
        return (~rows["is_allowed"].astype(bool)).astype(int)
    return rows["violation_type"].ne("none").astype(int)


def _top_dimension_values(
    detail: pd.DataFrame,
    column: str,
    limit: int,
) -> pd.Index:
    return (
        detail.groupby(column)
        .agg(
            max_risk_score=("max_risk_score", "max"),
            avg_risk_score=("avg_risk_score", "mean"),
            violation_count=("violation_count", "sum"),
            event_count=("event_count", "sum"),
        )
        .sort_values(
            by=["max_risk_score", "violation_count", "event_count", "avg_risk_score"],
            ascending=[False, False, False, False],
        )
        .head(limit)
        .index
    )


def _join_unique(values: pd.Series) -> str:
    normalized_values: list[str] = []
    for value in values:
        if pd.isna(value):
            continue
        text = str(value)
        if text not in normalized_values:
            normalized_values.append(text)
    return ", ".join(sorted(normalized_values))
