from datetime import datetime
from html import escape
from pathlib import Path
from typing import Any

import pandas as pd

from flowguardgraph.dashboard_utils import build_risk_heatmap_detail_dataframe


PROJECT_NAME = "FlowGuardGraph"


def generate_markdown_report(
    dataset_name: str,
    summaries: dict[str, Any],
    risk_dataframe: pd.DataFrame,
    source_target_dataframe: pd.DataFrame | None = None,
    output_dir: str = "outputs",
    detection_time: str | None = None,
) -> str:
    output_path = Path(output_dir) / "flowguard_report.md"
    output_path.parent.mkdir(parents=True, exist_ok=True)

    report_data = _build_report_data(
        dataset_name=dataset_name,
        summaries=summaries,
        risk_dataframe=risk_dataframe,
        source_target_dataframe=source_target_dataframe,
        detection_time=detection_time,
    )
    output_path.write_text(_render_markdown(report_data), encoding="utf-8")
    return str(output_path)


def generate_html_report(
    dataset_name: str,
    summaries: dict[str, Any],
    risk_dataframe: pd.DataFrame,
    source_target_dataframe: pd.DataFrame | None = None,
    output_dir: str = "outputs",
    detection_time: str | None = None,
) -> str:
    output_path = Path(output_dir) / "flowguard_report.html"
    output_path.parent.mkdir(parents=True, exist_ok=True)

    report_data = _build_report_data(
        dataset_name=dataset_name,
        summaries=summaries,
        risk_dataframe=risk_dataframe,
        source_target_dataframe=source_target_dataframe,
        detection_time=detection_time,
    )
    output_path.write_text(_render_html(report_data), encoding="utf-8")
    return str(output_path)


def _build_report_data(
    dataset_name: str,
    summaries: dict[str, Any],
    risk_dataframe: pd.DataFrame,
    source_target_dataframe: pd.DataFrame | None,
    detection_time: str | None,
) -> dict[str, Any]:
    source_target_dataframe = (
        source_target_dataframe
        if source_target_dataframe is not None
        else build_risk_heatmap_detail_dataframe(risk_dataframe)
    )
    metrics = _extract_metrics(summaries, risk_dataframe)

    return {
        "project_name": PROJECT_NAME,
        "dataset_name": dataset_name,
        "detection_time": detection_time or datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "metrics": metrics,
        "top_events": _build_top_events(risk_dataframe),
        "top_paths": _build_top_paths(source_target_dataframe),
        "risk_distribution": _build_distribution_table(
            risk_dataframe,
            "risk_level",
            ["high", "medium", "low"],
        ),
        "violation_distribution": _build_distribution_table(
            risk_dataframe,
            "violation_type",
            ["external_unapproved", "purpose_mismatch", "unregistered_flow", "none"],
        ),
        "conclusion": _build_conclusion(metrics),
    }


def _extract_metrics(
    summaries: dict[str, Any],
    risk_dataframe: pd.DataFrame,
) -> dict[str, int]:
    compliance = summaries.get("compliance", {})
    risk = summaries.get("risk", {})
    ml = summaries.get("ml", {})
    delta = summaries.get("delta", {})

    return {
        "总事件数": int(compliance.get("total_events", len(risk_dataframe))),
        "违规事件数": int(compliance.get("violation_events", 0)),
        "高风险事件数": int(risk.get("high_risk_events", 0)),
        "外部传输事件数": int(risk.get("external_events", 0)),
        "ML 异常事件数": int(ml.get("ml_anomaly_events", 0)),
        "Delta 边数量": int(delta.get("num_delta_edges", 0)),
    }


def _build_top_events(risk_dataframe: pd.DataFrame) -> pd.DataFrame:
    columns = [
        "timestamp",
        "source",
        "target",
        "field",
        "violation_type",
        "risk_score",
        "hybrid_risk_score",
        "risk_level",
        "hybrid_risk_level",
    ]
    if risk_dataframe.empty:
        return pd.DataFrame(columns=columns)

    existing_columns = [column for column in columns if column in risk_dataframe.columns]
    sort_column = (
        "hybrid_risk_score"
        if "hybrid_risk_score" in risk_dataframe.columns
        else "risk_score"
    )
    return (
        risk_dataframe.sort_values(
            by=[sort_column, "risk_score"],
            ascending=[False, False],
        )
        .head(10)[existing_columns]
        .reset_index(drop=True)
    )


def _build_top_paths(source_target_dataframe: pd.DataFrame) -> pd.DataFrame:
    columns = [
        "source",
        "target",
        "fields",
        "max_risk_score",
        "avg_risk_score",
        "event_count",
        "violation_types",
    ]
    if source_target_dataframe.empty:
        return pd.DataFrame(columns=columns)

    existing_columns = [
        column for column in columns if column in source_target_dataframe.columns
    ]
    return (
        source_target_dataframe.sort_values(
            by=["max_risk_score", "avg_risk_score", "event_count"],
            ascending=[False, False, False],
        )
        .head(10)[existing_columns]
        .reset_index(drop=True)
    )


def _build_distribution_table(
    risk_dataframe: pd.DataFrame,
    column: str,
    ordered_values: list[str],
) -> pd.DataFrame:
    if risk_dataframe.empty or column not in risk_dataframe.columns:
        return pd.DataFrame({column: ordered_values, "count": [0] * len(ordered_values)})

    return (
        risk_dataframe[column]
        .value_counts()
        .reindex(ordered_values, fill_value=0)
        .rename_axis(column)
        .reset_index(name="count")
    )


def _build_conclusion(metrics: dict[str, int]) -> str:
    high_risk_events = metrics["高风险事件数"]
    violation_events = metrics["违规事件数"]
    ml_anomaly_events = metrics["ML 异常事件数"]

    if high_risk_events > 0:
        return (
            "检测结果显示存在高风险数据流，建议优先排查未授权外部传输、"
            "敏感字段外传和未知外部目标。"
        )
    if violation_events > 0 or ml_anomaly_events > 0:
        return "检测结果显示存在可疑或不一致数据流，建议结合业务场景进一步复核。"
    return "当前数据集未发现明显高风险外传路径，可持续接入更多日志进行监测。"


def _render_markdown(report_data: dict[str, Any]) -> str:
    metrics = report_data["metrics"]
    lines = [
        f"# {report_data['project_name']} 检测报告",
        "",
        f"- 项目名称：{report_data['project_name']}",
        f"- 数据集名称：{report_data['dataset_name']}",
        f"- 检测时间：{report_data['detection_time']}",
        "",
        "## 检测结果总览",
        "",
        _dict_to_markdown_table(metrics),
        "",
        "## Top 10 高风险事件",
        "",
        _dataframe_to_markdown_table(report_data["top_events"]),
        "",
        "## Top 10 高风险 source-target 路径",
        "",
        _dataframe_to_markdown_table(report_data["top_paths"]),
        "",
        "## 风险等级分布",
        "",
        _dataframe_to_markdown_table(report_data["risk_distribution"]),
        "",
        "## 违规类型分布",
        "",
        _dataframe_to_markdown_table(report_data["violation_distribution"]),
        "",
        "## 简短结论",
        "",
        report_data["conclusion"],
        "",
    ]
    return "\n".join(lines)


def _render_html(report_data: dict[str, Any]) -> str:
    metrics_rows = "".join(
        f"<tr><th>{escape(key)}</th><td>{value}</td></tr>"
        for key, value in report_data["metrics"].items()
    )
    return f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <title>{escape(report_data['project_name'])} 检测报告</title>
  <style>
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      margin: 32px;
      color: #1f2933;
      line-height: 1.55;
    }}
    h1, h2 {{ color: #152238; }}
    table {{
      border-collapse: collapse;
      width: 100%;
      margin: 12px 0 24px;
      font-size: 14px;
    }}
    th, td {{
      border: 1px solid #d8dde6;
      padding: 8px 10px;
      text-align: left;
      vertical-align: top;
    }}
    th {{ background: #f4f7fb; }}
    .meta {{ color: #586273; }}
    .conclusion {{
      border-left: 4px solid #d62728;
      background: #fff7f7;
      padding: 10px 14px;
    }}
  </style>
</head>
<body>
  <h1>{escape(report_data['project_name'])} 检测报告</h1>
  <p class="meta">数据集名称：{escape(str(report_data['dataset_name']))}</p>
  <p class="meta">检测时间：{escape(str(report_data['detection_time']))}</p>

  <h2>检测结果总览</h2>
  <table>{metrics_rows}</table>

  <h2>Top 10 高风险事件</h2>
  {report_data['top_events'].to_html(index=False, escape=True)}

  <h2>Top 10 高风险 source-target 路径</h2>
  {report_data['top_paths'].to_html(index=False, escape=True)}

  <h2>风险等级分布</h2>
  {report_data['risk_distribution'].to_html(index=False, escape=True)}

  <h2>违规类型分布</h2>
  {report_data['violation_distribution'].to_html(index=False, escape=True)}

  <h2>简短结论</h2>
  <p class="conclusion">{escape(report_data['conclusion'])}</p>
</body>
</html>
"""


def _dict_to_markdown_table(values: dict[str, int]) -> str:
    rows = pd.DataFrame(
        [{"指标": key, "数值": value} for key, value in values.items()]
    )
    return _dataframe_to_markdown_table(rows)


def _dataframe_to_markdown_table(dataframe: pd.DataFrame) -> str:
    if dataframe.empty:
        return "无数据。"

    columns = [str(column) for column in dataframe.columns]
    lines = [
        "| " + " | ".join(columns) + " |",
        "| " + " | ".join(["---"] * len(columns)) + " |",
    ]
    for _, row in dataframe.iterrows():
        values = [_escape_markdown_value(row[column]) for column in dataframe.columns]
        lines.append("| " + " | ".join(values) + " |")
    return "\n".join(lines)


def _escape_markdown_value(value: Any) -> str:
    if pd.isna(value):
        return ""
    text = str(value).replace("\n", " ").replace("|", "\\|")
    return text
