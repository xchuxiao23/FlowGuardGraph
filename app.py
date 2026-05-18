from pathlib import Path
from typing import Any

import networkx as nx
import pandas as pd
import plotly.graph_objects as go
import streamlit as st
import streamlit.components.v1 as components

from flowguardgraph.compliance_checker import (
    check_compliance,
    summarize_compliance_results,
)
from flowguardgraph.dashboard_utils import (
    HEATMAP_METRICS,
    build_risk_heatmap_dataframe,
    build_risk_heatmap_detail_dataframe,
)
from flowguardgraph.delta_analyzer import (
    build_delta_graph,
    get_delta_edges_table,
    summarize_delta_graph,
)
from flowguardgraph.graph_builder import (
    build_policy_graph,
    build_risk_graph,
    build_runtime_graph,
    summarize_graph,
)
from flowguardgraph.log_parser import load_flow_logs
from flowguardgraph.ml_anomaly_detector import (
    run_isolation_forest,
    summarize_ml_results,
)
from flowguardgraph.policy_loader import load_policy
from flowguardgraph.report_generator import (
    generate_html_report,
    generate_markdown_report,
)
from flowguardgraph.risk_analyzer import (
    analyze_risks,
    load_sensitive_fields,
    summarize_risk_results,
)
from flowguardgraph.visualizer import (
    visualize_graph,
    visualize_policy_runtime_risk_graphs,
)


PAGE_TITLE = "FlowGuardGraph"
PAGE_SUBTITLE = "数据流合规检测与非计划外传风险预警原型系统"
PAGE_DESCRIPTION = (
    "面向数据安全治理场景，融合声明规则、一致性检测、敏感字段识别与机器学习异常检测，"
    "实现非计划数据外传风险识别与可视化预警。"
)

DATASET_PATHS = {
    "demo_small": {
        "policy": "examples/demo_small/policy_declaration.yaml",
        "logs": "examples/demo_small/actual_flow_logs.csv",
        "sensitive": "examples/demo_small/sensitive_fields.json",
    },
    "demo_medium": {
        "policy": "examples/demo_medium/policy_declaration.yaml",
        "logs": "examples/demo_medium/actual_flow_logs.csv",
        "sensitive": "examples/demo_medium/sensitive_fields.json",
    },
    "demo_large": {
        "policy": "examples/demo_large/policy_declaration.yaml",
        "logs": "examples/demo_large/actual_flow_logs.csv",
        "sensitive": "examples/demo_large/sensitive_fields.json",
    },
}

DEFAULT_DATASET = "demo_medium"
DEFAULT_POLICY_PATH = DATASET_PATHS[DEFAULT_DATASET]["policy"]
DEFAULT_LOG_PATH = DATASET_PATHS[DEFAULT_DATASET]["logs"]
DEFAULT_SENSITIVE_PATH = DATASET_PATHS[DEFAULT_DATASET]["sensitive"]

GRAPH_OPTIONS = {
    "Risk Graph": "risk",
    "Delta Graph": "delta",
    "Policy Graph": "policy",
    "Runtime Graph": "runtime",
}

GRAPH_DETAILS = {
    "risk": {
        "title": "Risk Graph：非计划数据外传风险图",
        "description": "展示基于声明—行为一致性比对、敏感字段识别和风险评分得到的高风险数据外传路径。",
    },
    "delta": {
        "title": "Delta Graph：声明—行为差异图",
        "description": "该图展示实际数据流与声明数据流之间的差异，突出未声明外传、用途不一致和高风险敏感字段外传路径。",
    },
    "policy": {
        "title": "Policy Graph：声明允许的数据流图",
        "description": "展示数据处理者声明允许的数据流路径，可作为合规检测基准图。",
    },
    "runtime": {
        "title": "Runtime Graph：实际发生的数据流图",
        "description": "展示日志中实际发生的数据流路径，用于与声明规则进行一致性比对。",
    },
}

RISK_TABLE_COLUMNS = [
    "timestamp",
    "user",
    "source",
    "target",
    "field",
    "action",
    "purpose",
    "is_allowed",
    "violation_type",
    "reason",
    "sensitivity_level",
    "external_target",
    "risk_score",
    "risk_level",
    "risk_reason",
    "ml_anomaly_score",
    "ml_is_anomaly",
    "hybrid_risk_score",
    "hybrid_risk_level",
    "ml_reason",
    "volume",
]

RISK_EVENT_DISPLAY_COLUMNS = [
    "timestamp",
    "source",
    "target",
    "field",
    "violation_type",
    "sensitivity_level",
    "risk_score",
    "hybrid_risk_score",
    "risk_level",
    "hybrid_risk_level",
    "ml_anomaly_score",
    "risk_reason",
]


st.set_page_config(
    page_title="FlowGuardGraph",
    page_icon="🛡️",
    layout="wide",
)


def build_risk_dataframe(
    risk_results: list[Any],
    ml_results: list[Any] | None = None,
) -> pd.DataFrame:
    rows = []
    ml_results = ml_results or []
    ml_by_index = {index: ml_result for index, ml_result in enumerate(ml_results)}

    for index, risk_result in enumerate(risk_results):
        compliance = risk_result.compliance_result
        event = compliance.event
        ml_result = ml_by_index.get(index)
        rows.append(
            {
                "timestamp": event.timestamp,
                "user": event.user,
                "source": event.source,
                "target": event.target,
                "field": event.field,
                "action": event.action,
                "purpose": event.purpose,
                "is_allowed": compliance.is_allowed,
                "violation_type": compliance.violation_type,
                "reason": compliance.reason,
                "sensitivity_level": risk_result.sensitivity_level,
                "external_target": risk_result.external_target,
                "risk_score": risk_result.risk_score,
                "risk_level": risk_result.risk_level,
                "risk_reason": risk_result.risk_reason,
                "ml_anomaly_score": (
                    ml_result.ml_anomaly_score if ml_result is not None else None
                ),
                "ml_is_anomaly": (
                    ml_result.ml_is_anomaly if ml_result is not None else False
                ),
                "hybrid_risk_score": (
                    ml_result.hybrid_risk_score
                    if ml_result is not None
                    else risk_result.risk_score
                ),
                "hybrid_risk_level": (
                    ml_result.hybrid_risk_level
                    if ml_result is not None
                    else risk_result.risk_level
                ),
                "ml_reason": (
                    ml_result.ml_reason
                    if ml_result is not None
                    else "未启用机器学习异常检测。"
                ),
                "volume": event.volume,
            }
        )

    dataframe = pd.DataFrame(rows, columns=RISK_TABLE_COLUMNS)
    if not dataframe.empty:
        sort_column = "hybrid_risk_score" if ml_results else "risk_score"
        dataframe = dataframe.sort_values(
            by=[sort_column, "risk_score", "timestamp"],
            ascending=[False, False, True],
        )
    return dataframe


def run_detection(
    policy_path: str,
    log_path: str,
    sensitive_path: str,
    enable_ml_anomaly: bool,
    contamination: float,
) -> dict[str, Any]:
    policy = load_policy(policy_path)
    events = load_flow_logs(log_path)
    compliance_results = check_compliance(events, policy)
    sensitive_map = load_sensitive_fields(sensitive_path)
    risk_results = analyze_risks(compliance_results, sensitive_map)
    ml_results = (
        run_isolation_forest(risk_results, contamination=contamination)
        if enable_ml_anomaly
        else []
    )

    policy_graph = build_policy_graph(policy)
    runtime_graph = build_runtime_graph(events)
    risk_graph = build_risk_graph(risk_results)
    delta_graph = build_delta_graph(risk_results)

    standalone_html_paths = visualize_policy_runtime_risk_graphs(
        policy_graph,
        runtime_graph,
        risk_graph,
        include_header=True,
    )
    standalone_html_paths["delta"] = visualize_graph(
        delta_graph,
        "outputs/delta_graph.html",
        graph_title=GRAPH_DETAILS["delta"]["title"],
        graph_description=GRAPH_DETAILS["delta"]["description"],
        include_header=True,
    )
    compact_html_paths = generate_compact_graph_html(
        policy_graph,
        runtime_graph,
        risk_graph,
        delta_graph,
    )

    graphs = {
        "policy": policy_graph,
        "runtime": runtime_graph,
        "risk": risk_graph,
        "delta": delta_graph,
    }

    return {
        "paths": {
            "policy": policy_path,
            "logs": log_path,
            "sensitive": sensitive_path,
        },
        "policy": policy,
        "events": events,
        "compliance_results": compliance_results,
        "risk_results": risk_results,
        "ml_results": ml_results,
        "graphs": graphs,
        "summaries": {
            "compliance": summarize_compliance_results(compliance_results),
            "risk": summarize_risk_results(risk_results),
            "ml": summarize_ml_results(ml_results),
            "graphs": {
                "policy": summarize_graph(policy_graph),
                "runtime": summarize_graph(runtime_graph),
                "risk": summarize_graph(risk_graph),
                "delta": summarize_graph(delta_graph),
            },
            "delta": summarize_delta_graph(delta_graph),
        },
        "ml_enabled": enable_ml_anomaly,
        "ml_contamination": contamination,
        "risk_dataframe": build_risk_dataframe(risk_results, ml_results),
        "delta_dataframe": get_delta_edges_table(delta_graph),
        "html_paths": {
            "standalone": standalone_html_paths,
            "compact": compact_html_paths,
        },
    }


def generate_compact_graph_html(
    policy_graph: nx.DiGraph,
    runtime_graph: nx.DiGraph,
    risk_graph: nx.DiGraph,
    delta_graph: nx.DiGraph,
) -> dict[str, str]:
    return {
        "policy": visualize_graph(
            policy_graph,
            "outputs/streamlit_policy_graph.html",
            height="780px",
            graph_title=GRAPH_DETAILS["policy"]["title"],
            graph_description=GRAPH_DETAILS["policy"]["description"],
            include_header=False,
        ),
        "runtime": visualize_graph(
            runtime_graph,
            "outputs/streamlit_runtime_graph.html",
            height="780px",
            graph_title=GRAPH_DETAILS["runtime"]["title"],
            graph_description=GRAPH_DETAILS["runtime"]["description"],
            include_header=False,
        ),
        "risk": visualize_graph(
            risk_graph,
            "outputs/streamlit_risk_graph.html",
            height="780px",
            graph_title=GRAPH_DETAILS["risk"]["title"],
            graph_description=GRAPH_DETAILS["risk"]["description"],
            include_header=False,
        ),
        "delta": visualize_graph(
            delta_graph,
            "outputs/streamlit_delta_graph.html",
            height="780px",
            graph_title=GRAPH_DETAILS["delta"]["title"],
            graph_description=GRAPH_DETAILS["delta"]["description"],
            include_header=False,
        ),
    }


def render_default_state(
    policy_path: str,
    log_path: str,
    sensitive_path: str,
    dataset_choice: str,
) -> None:
    _ = (policy_path, log_path, sensitive_path)
    st.info("请在左侧选择数据集并点击“运行检测”。")

    st.divider()
    st.markdown("### 核心能力")
    capability_columns = st.columns(4)
    capabilities = [
        (
            "声明—行为一致性检测",
            "比对声明允许的数据流与实际日志行为，识别不一致流动。",
        ),
        (
            "非计划数据外传识别",
            "发现未授权外部传输、用途不一致、敏感字段外传等风险。",
        ),
        (
            "机器学习异常检测",
            "使用 Isolation Forest 对数据流行为特征进行无监督异常检测。",
        ),
        (
            "风险图谱可视化",
            "构建 Risk Graph、Delta Graph 和 source-target 风险热力图。",
        ),
    ]
    for column, (title, description) in zip(capability_columns, capabilities, strict=True):
        with column:
            with st.container(border=True):
                st.markdown(f"#### {title}")
                st.write(description)

    st.divider()
    st.markdown("### 检测流程")
    st.markdown(
        "**声明规则** → **实际日志** → **一致性检测** → "
        "**ML 异常检测** → **风险评分** → **可视化预警**"
    )

    st.divider()
    st.markdown("### 示例数据集")
    dataset_descriptions = {
        "demo_small": "轻量测试数据集，适合快速功能验证。",
        "demo_medium": (
            "包含中等规模模拟数据流日志，覆盖正常流动、未授权外传、用途不一致、"
            "敏感字段泄露、未知外部目标和异常行为等场景。"
        ),
        "demo_large": "大规模模拟数据集，适合压力测试和统计分析展示。",
        "custom": "用户自定义数据路径。",
    }
    st.markdown(f"**当前示例数据集：{dataset_choice}**")
    st.write(dataset_descriptions.get(dataset_choice, "用户自定义数据路径。"))

    st.divider()
    st.info(
        "请在左侧选择数据集并点击“运行检测”。系统将自动生成风险总览、"
        "Risk Graph、Delta Graph、风险事件表和统计分析结果。"
    )


def filter_graph_for_display(
    graph: nx.DiGraph,
    graph_key: str,
    only_violation_edges: bool,
    only_external_edges: bool,
    top_k_edges: int,
) -> nx.DiGraph:
    if graph_key not in {"risk", "delta"}:
        return graph

    selected_edges = []
    for source, target, attrs in graph.edges(data=True):
        if only_violation_edges and attrs.get("is_allowed") is not False:
            continue
        if only_external_edges and not _is_external_target(graph, target):
            continue
        selected_edges.append((source, target, attrs))

    selected_edges = sorted(
        selected_edges,
        key=lambda item: (
            item[2].get("max_risk_score", item[2].get("risk_score", 0.0)),
            item[2].get("event_count", 0),
        ),
        reverse=True,
    )[:top_k_edges]

    filtered_graph = nx.DiGraph()
    for source, target, attrs in selected_edges:
        filtered_graph.add_node(source, **graph.nodes[source])
        filtered_graph.add_node(target, **graph.nodes[target])
        filtered_graph.add_edge(source, target, **attrs)

    return filtered_graph


def _is_external_target(graph: nx.DiGraph, target: str) -> bool:
    node_type = graph.nodes[target].get("node_type")
    normalized = target.lower()
    external_keywords = (
        "external",
        "partner",
        "crm",
        "unknown",
        "third_party",
        "shadow",
    )
    return node_type == "external" or any(keyword in normalized for keyword in external_keywords)


def summarize_display_graph(graph: nx.DiGraph, graph_key: str) -> dict[str, int]:
    if graph_key == "delta":
        return summarize_delta_graph(graph)
    return summarize_graph(graph)


def render_metrics(result: dict[str, Any]) -> None:
    compliance_summary = result["summaries"]["compliance"]
    risk_summary = result["summaries"]["risk"]
    ml_summary = result["summaries"]["ml"]
    delta_summary = result["summaries"]["delta"]

    st.markdown("### 检测结果总览")
    columns = st.columns(6)
    columns[0].metric("总事件数", compliance_summary["total_events"])
    columns[1].metric("违规事件", compliance_summary["violation_events"])
    columns[2].metric("高风险事件", risk_summary["high_risk_events"])
    columns[3].metric("外部传输", risk_summary["external_events"])
    columns[4].metric("ML 异常", ml_summary["ml_anomaly_events"])
    columns[5].metric("Delta 边", delta_summary["num_delta_edges"])


def render_process() -> None:
    st.markdown("### 项目检测流程")
    st.markdown(
        "**声明规则** → **实际日志** → **数据流图构建** → **一致性检测** → "
        "**敏感字段识别** → **风险评分** → **可视化预警**"
    )


def render_ml_description(result: dict[str, Any]) -> None:
    if not result["ml_enabled"]:
        return

    st.info(
        "机器学习异常检测采用 Isolation Forest 对数据流行为特征进行无监督建模，"
        "用于发现与整体行为分布不一致的数据流事件。该结果与规则风险分数融合形成 "
        "hybrid_risk_score。"
    )


def render_graph_tab(
    result: dict[str, Any],
    graph_choice: str,
    only_violation_edges: bool,
    only_external_edges: bool,
    top_k_edges: int,
) -> None:
    graph_key = GRAPH_OPTIONS[graph_choice]
    graph_info = GRAPH_DETAILS[graph_key]
    base_graph = result["graphs"][graph_key]
    display_graph = filter_graph_for_display(
        base_graph,
        graph_key,
        only_violation_edges,
        only_external_edges,
        top_k_edges,
    )
    graph_summary = summarize_display_graph(display_graph, graph_key)

    if graph_key in {"risk", "delta"}:
        html_path = Path(f"outputs/streamlit_filtered_{graph_key}_graph.html")
        visualize_graph(
            display_graph,
            str(html_path),
            height="780px",
            graph_title=graph_info["title"],
            graph_description=graph_info["description"],
            include_header=False,
        )
    else:
        html_path = Path(result["html_paths"]["compact"][graph_key])

    st.markdown(f"### {graph_info['title']}")
    st.write(graph_info["description"])

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("节点数", graph_summary["num_nodes"])
    col2.metric("边数", graph_summary["num_edges"])
    if graph_key == "delta":
        col3.metric("高风险边数", graph_summary["num_high_risk_edges"])
        col4.metric("违规边数", graph_summary["num_external_unapproved_edges"])
    else:
        col3.metric("高风险边数", graph_summary["num_high_risk_edges"])
        col4.metric("违规边数", graph_summary["num_violation_edges"])

    if not html_path.exists():
        st.error(f"图谱 HTML 文件不存在：{html_path}")
        return

    components.html(
        html_path.read_text(encoding="utf-8"),
        height=820,
        scrolling=False,
    )
    render_graph_legend()


def render_graph_legend() -> None:
    with st.expander("图例说明", expanded=False):
        st.markdown(
            """
            节点：蓝色圆形表示内部系统或内部数据资产；橙色三角形表示外部系统；红色菱形表示未知或高危外部系统。

            边：绿色实线表示低风险或正常流动；橙色虚线表示中风险或声明用途不一致；红色粗虚线表示高风险非计划外传；灰色实线表示声明允许的数据流。
            """
        )


def get_filtered_risk_dataframe(
    risk_dataframe: pd.DataFrame,
    selected_risk_levels: list[str],
    use_hybrid_level: bool,
) -> pd.DataFrame:
    if not selected_risk_levels:
        return risk_dataframe.iloc[0:0]
    level_column = "hybrid_risk_level" if use_hybrid_level else "risk_level"
    return risk_dataframe[risk_dataframe[level_column].isin(selected_risk_levels)]


def sort_risk_dataframe(risk_dataframe: pd.DataFrame, ml_enabled: bool) -> pd.DataFrame:
    if risk_dataframe.empty:
        return risk_dataframe
    sort_column = "hybrid_risk_score" if ml_enabled else "risk_score"
    return risk_dataframe.sort_values(
        by=[sort_column, "risk_score", "timestamp"],
        ascending=[False, False, True],
    )


def top_event_columns(ml_enabled: bool) -> list[str]:
    if ml_enabled:
        return [
            "field",
            "source",
            "target",
            "hybrid_risk_score",
            "risk_level",
            "violation_type",
        ]
    return ["field", "source", "target", "risk_score", "risk_level", "violation_type"]


def render_risk_events_tab(
    risk_dataframe: pd.DataFrame,
    delta_dataframe: pd.DataFrame,
    selected_risk_levels: list[str],
    ml_enabled: bool,
) -> None:
    filtered = get_filtered_risk_dataframe(
        risk_dataframe,
        selected_risk_levels,
        use_hybrid_level=ml_enabled,
    )
    filtered = sort_risk_dataframe(filtered, ml_enabled)

    st.markdown("### Top 高风险事件")
    top_events = sort_risk_dataframe(risk_dataframe, ml_enabled)
    st.dataframe(
        top_events.head(8)[top_event_columns(ml_enabled)],
        use_container_width=True,
        hide_index=True,
        height=280,
    )

    st.markdown("### 完整风险事件表")
    sort_label = "hybrid_risk_score" if ml_enabled else "risk_score"
    st.caption(
        f"已按 {sort_label} 降序排列；当前显示 {len(filtered)} / {len(risk_dataframe)} 条。"
    )
    st.dataframe(
        filtered[RISK_EVENT_DISPLAY_COLUMNS],
        use_container_width=True,
        hide_index=True,
        height=520,
    )

    with st.expander("查看完整 reason / ml_reason 字段", expanded=False):
        reason_columns = [
            "timestamp",
            "source",
            "target",
            "field",
            "reason",
            "risk_reason",
            "ml_reason",
        ]
        st.dataframe(
            filtered[reason_columns],
            use_container_width=True,
            hide_index=True,
            height=360,
        )

    with st.expander("查看 Delta 差异边", expanded=False):
        render_delta_edges_table(delta_dataframe)


def render_delta_edges_table(delta_dataframe: pd.DataFrame) -> None:
    st.markdown("### Delta 差异边表")
    if delta_dataframe.empty:
        st.info("当前结果中没有差异边。")
        return

    st.dataframe(delta_dataframe, use_container_width=True, hide_index=True)


def render_risk_overview_tab(result: dict[str, Any], dataset_name: str) -> None:
    risk_dataframe = result["risk_dataframe"]
    ml_enabled = result["ml_enabled"]

    st.write("当前数据集的非计划数据外传风险概览。")
    left, right = st.columns([1.25, 1])

    with left:
        st.markdown("#### Top 5 高风险事件")
        top_events = sort_risk_dataframe(risk_dataframe, ml_enabled)
        st.dataframe(
            top_events.head(5)[top_event_columns(ml_enabled)],
            use_container_width=True,
            hide_index=True,
            height=240,
        )

    with right:
        st.markdown("#### 风险等级分布")
        risk_counts = (
            risk_dataframe["risk_level"]
            .value_counts()
            .reindex(["high", "medium", "low"], fill_value=0)
            .rename_axis("risk_level")
            .reset_index(name="count")
        )
        st.bar_chart(risk_counts, x="risk_level", y="count")

        st.markdown("#### 违规类型分布")
        violation_counts = (
            risk_dataframe["violation_type"]
            .value_counts()
            .reindex(
                ["external_unapproved", "purpose_mismatch", "unregistered_flow", "none"],
                fill_value=0,
            )
            .rename_axis("violation_type")
            .reset_index(name="count")
        )
        st.bar_chart(violation_counts, x="violation_type", y="count")

    st.divider()
    st.markdown("#### Top 10 高风险数据流路径")
    path_columns = [
        "source",
        "target",
        "fields",
        "max_risk_score",
        "event_count",
        "violation_types",
    ]
    st.dataframe(
        build_risk_heatmap_detail_dataframe(risk_dataframe).head(10)[path_columns],
        use_container_width=True,
        hide_index=True,
        height=320,
    )

    st.divider()
    st.markdown("#### 检测报告")
    if st.button("导出检测报告", type="secondary"):
        source_target_dataframe = build_risk_heatmap_detail_dataframe(risk_dataframe)
        markdown_path = generate_markdown_report(
            dataset_name=dataset_name,
            summaries=result["summaries"],
            risk_dataframe=risk_dataframe,
            source_target_dataframe=source_target_dataframe,
        )
        html_path = generate_html_report(
            dataset_name=dataset_name,
            summaries=result["summaries"],
            risk_dataframe=risk_dataframe,
            source_target_dataframe=source_target_dataframe,
        )
        st.session_state["flowguardgraph_report_paths"] = {
            "markdown": markdown_path,
            "html": html_path,
        }

    report_paths = st.session_state.get("flowguardgraph_report_paths")
    if report_paths:
        st.success("检测报告已生成。")
        st.code(
            "\n".join(
                [
                    f"Markdown: {report_paths['markdown']}",
                    f"HTML: {report_paths['html']}",
                ]
            )
        )
        report_left, report_right = st.columns(2)
        markdown_file = Path(report_paths["markdown"])
        html_file = Path(report_paths["html"])
        if markdown_file.exists():
            report_left.download_button(
                "下载 Markdown 报告",
                data=markdown_file.read_text(encoding="utf-8"),
                file_name=markdown_file.name,
                mime="text/markdown",
            )
        if html_file.exists():
            report_right.download_button(
                "下载 HTML 报告",
                data=html_file.read_text(encoding="utf-8"),
                file_name=html_file.name,
                mime="text/html",
            )


def render_stats_tab(risk_dataframe: pd.DataFrame, ml_enabled: bool) -> None:
    left, middle, right = st.columns(3)
    risk_counts = (
        risk_dataframe["risk_level"]
        .value_counts()
        .reindex(["high", "medium", "low"], fill_value=0)
        .rename_axis("risk_level")
        .reset_index(name="count")
    )
    violation_counts = (
        risk_dataframe["violation_type"]
        .value_counts()
        .reindex(
            ["external_unapproved", "purpose_mismatch", "unregistered_flow", "none"],
            fill_value=0,
        )
        .rename_axis("violation_type")
        .reset_index(name="count")
    )
    transfer_counts = (
        risk_dataframe["external_target"]
        .map({True: "external", False: "internal"})
        .value_counts()
        .reindex(["external", "internal"], fill_value=0)
        .rename_axis("transfer_type")
        .reset_index(name="count")
    )

    with left:
        st.markdown("#### 风险等级分布")
        st.bar_chart(risk_counts, x="risk_level", y="count")

    with middle:
        st.markdown("#### 违规类型分布")
        st.bar_chart(violation_counts, x="violation_type", y="count")

    with right:
        st.markdown("#### 外部/内部传输")
        st.bar_chart(transfer_counts, x="transfer_type", y="count")

    st.divider()
    render_risk_heatmap(risk_dataframe)

    if ml_enabled:
        st.divider()
        render_ml_stats(risk_dataframe)


def render_dataset_scale_stats(risk_dataframe: pd.DataFrame) -> None:
    st.markdown("#### 数据集规模统计")
    col1, col2, col3, col4, col5 = st.columns(5)
    col1.metric("总事件数", len(risk_dataframe))
    col2.metric("source 数量", risk_dataframe["source"].nunique())
    col3.metric("target 数量", risk_dataframe["target"].nunique())
    col4.metric("field 数量", risk_dataframe["field"].nunique())
    col5.metric(
        "外部系统数量",
        risk_dataframe.loc[risk_dataframe["external_target"], "target"].nunique(),
    )


def render_risk_heatmap(risk_dataframe: pd.DataFrame) -> None:
    st.markdown("#### source × target 平均风险分数热力图")
    if risk_dataframe.empty:
        st.info("当前没有可用于绘制热力图的数据。")
        return

    control_left, control_middle, control_right = st.columns(3)
    with control_left:
        top_sources = st.slider(
            "显示 Top-N source",
            min_value=5,
            max_value=30,
            value=15,
            step=1,
        )
    with control_middle:
        top_targets = st.slider(
            "显示 Top-N target",
            min_value=5,
            max_value=30,
            value=12,
            step=1,
        )
    with control_right:
        heatmap_metric = st.selectbox(
            "热力图指标",
            options=HEATMAP_METRICS,
            index=0,
        )

    detail = build_risk_heatmap_detail_dataframe(risk_dataframe)
    pivot = build_risk_heatmap_dataframe(
        risk_dataframe,
        top_sources=top_sources,
        top_targets=top_targets,
        metric=heatmap_metric,
    )
    if pivot.empty:
        st.info("当前筛选条件下没有可用于绘制热力图的数据。")
        return

    detail_lookup = detail.set_index(["source", "target"])
    customdata = []
    for source in pivot.index:
        row_values = []
        for target in pivot.columns:
            if (source, target) in detail_lookup.index:
                record = detail_lookup.loc[(source, target)]
                row_values.append(
                    [
                        source,
                        target,
                        record["avg_risk_score"],
                        record["max_risk_score"],
                        record["event_count"],
                        record["violation_count"],
                        record["high_risk_count"],
                        record["fields"],
                        record["violation_types"],
                    ]
                )
            else:
                row_values.append([source, target, 0, 0, 0, 0, 0, "", ""])
        customdata.append(row_values)

    colorbar_title = heatmap_metric
    heatmap_kwargs: dict[str, Any] = {
        "z": pivot.values,
        "x": pivot.columns,
        "y": pivot.index,
        "customdata": customdata,
        "colorscale": "Reds",
        "colorbar": {"title": colorbar_title},
        "hovertemplate": (
            "source: %{customdata[0]}<br>"
            "target: %{customdata[1]}<br>"
            "avg_risk_score: %{customdata[2]:.3f}<br>"
            "max_risk_score: %{customdata[3]:.3f}<br>"
            "event_count: %{customdata[4]}<br>"
            "violation_count: %{customdata[5]}<br>"
            "high_risk_count: %{customdata[6]}<br>"
            "fields: %{customdata[7]}<br>"
            "violation_types: %{customdata[8]}<br>"
            f"{heatmap_metric}: " + "%{z:.3f}<extra></extra>"
        ),
    }
    if heatmap_metric in {"avg_risk_score", "max_risk_score"}:
        heatmap_kwargs["zmin"] = 0
        heatmap_kwargs["zmax"] = 1

    source_count = len(pivot.index)
    target_count = len(pivot.columns)
    heatmap_height = max(650, min(1100, 65 * source_count + 260))

    fig = go.Figure(data=go.Heatmap(**heatmap_kwargs))
    fig.update_layout(
        title="source × target 平均风险分数热力图",
        xaxis_title="target",
        yaxis_title="source",
        height=heatmap_height,
        margin={"l": 120, "r": 80, "t": 80, "b": 160},
    )
    fig.update_xaxes(tickangle=-45, automargin=True)
    fig.update_yaxes(automargin=True)
    st.plotly_chart(fig, use_container_width=True)
    st.caption(
        f"当前展示 {source_count} 个 source × {target_count} 个 target。"
        "为避免大规模数据流图过于拥挤，热力图默认展示风险较高或事件较多的 "
        "Top-N source 和 target，可通过上方滑块调整展示范围。"
    )

    with st.expander("查看 source-target 风险矩阵表", expanded=False):
        styled_pivot = pivot.round(3).style.background_gradient(
            cmap="Reds",
            axis=None,
        )
        st.dataframe(styled_pivot, use_container_width=True)

    st.markdown("#### source-target 风险明细 Top 20")
    detail_sort_column = (
        heatmap_metric if heatmap_metric in detail.columns else "max_risk_score"
    )
    detail_top20 = detail.sort_values(
        by=[detail_sort_column, "max_risk_score", "avg_risk_score", "event_count"],
        ascending=[False, False, False, False],
    ).head(20)
    st.dataframe(detail_top20, use_container_width=True, hide_index=True)


def render_ml_stats(risk_dataframe: pd.DataFrame) -> None:
    st.markdown("### 机器学习异常检测统计")
    ml_left, ml_right = st.columns(2)
    ml_score_distribution = (
        pd.cut(
            risk_dataframe["ml_anomaly_score"].fillna(0),
            bins=[0, 0.25, 0.5, 0.75, 1.0],
            include_lowest=True,
        )
        .astype(str)
        .value_counts()
        .sort_index()
        .rename_axis("ml_anomaly_score_range")
        .reset_index(name="count")
    )
    hybrid_counts = (
        risk_dataframe["hybrid_risk_level"]
        .value_counts()
        .reindex(["high", "medium", "low"], fill_value=0)
        .rename_axis("hybrid_risk_level")
        .reset_index(name="count")
    )

    with ml_left:
        st.markdown("#### ML 异常分数分布")
        st.bar_chart(ml_score_distribution, x="ml_anomaly_score_range", y="count")

    with ml_right:
        st.markdown("#### Hybrid Risk Level 分布")
        st.bar_chart(hybrid_counts, x="hybrid_risk_level", y="count")

    st.markdown("#### 规则风险分数与 ML 异常分数对比")
    comparison_columns = [
        "timestamp",
        "source",
        "target",
        "field",
        "risk_score",
        "ml_anomaly_score",
        "hybrid_risk_score",
        "hybrid_risk_level",
    ]
    st.dataframe(
        risk_dataframe[comparison_columns],
        use_container_width=True,
        hide_index=True,
    )


def render_data_info_tab(result: dict[str, Any]) -> None:
    paths = result["paths"]
    with st.expander("项目简介", expanded=True):
        st.write(PAGE_DESCRIPTION)

    with st.expander("系统流程", expanded=False):
        st.markdown(
            "**声明规则** → **实际日志** → **一致性检测** → "
            "**ML 异常检测** → **风险图谱** → **可视化预警**"
        )

    with st.expander("当前数据路径", expanded=False):
        st.code(
            "\n".join(
                [
                    f"policy: {paths['policy']}",
                    f"logs: {paths['logs']}",
                    f"sensitive_fields: {paths['sensitive']}",
                ]
            )
        )

    with st.expander("风险评分公式", expanded=False):
        st.code(
            "risk_score = 0.4 * policy_violation\n"
            "           + 0.3 * sensitivity_score\n"
            "           + 0.2 * external_target\n"
            "           + 0.1 * purpose_mismatch"
        )

    with st.expander("Hybrid Risk 说明", expanded=False):
        st.write(
            "启用机器学习异常检测后，系统使用 hybrid_risk_score 融合规则风险分数"
            "和 Isolation Forest 异常分数，用于排序和预警。"
        )

    with st.expander("ML 异常检测说明", expanded=False):
        st.write(
            "机器学习异常检测采用 Isolation Forest 对数据流行为特征进行无监督建模，"
            "用于发现与整体行为分布不一致的数据流事件。"
        )

    with st.expander("示例数据说明", expanded=False):
        st.markdown(
            """
            - `policy_declaration.yaml`：声明允许的数据流规则
            - `actual_flow_logs.csv`：模拟实际数据流日志
            - `sensitive_fields.json`：敏感字段等级配置
            - `demo_sql.sql`：SQL 数据流解析示例
            """
        )

    with st.expander("使用步骤", expanded=False):
        st.markdown(
            """
            1. 在侧边栏选择示例数据集或自定义路径。
            2. 配置检测参数和图谱过滤条件。
            3. 点击“运行检测”。
            4. 在各 tab 中查看风险总览、图谱、事件表和统计分析。
            """
        )


def render_dashboard(
    result: dict[str, Any],
    dataset_name: str,
    graph_choice: str,
    selected_risk_levels: list[str],
    only_violation_edges: bool,
    only_external_edges: bool,
    top_k_edges: int,
) -> None:
    render_metrics(result)
    st.divider()

    overview_tab, graph_tab, risk_tab, stats_tab, info_tab = st.tabs(
        ["风险总览", "图谱监测", "风险事件", "统计分析", "数据说明"]
    )
    with overview_tab:
        render_risk_overview_tab(result, dataset_name)
    with graph_tab:
        render_graph_tab(
            result,
            graph_choice,
            only_violation_edges,
            only_external_edges,
            top_k_edges,
        )
    with risk_tab:
        render_risk_events_tab(
            result["risk_dataframe"],
            result["delta_dataframe"],
            selected_risk_levels,
            result["ml_enabled"],
        )
    with stats_tab:
        render_stats_tab(result["risk_dataframe"], result["ml_enabled"])
    with info_tab:
        render_data_info_tab(result)


def render_sidebar() -> dict[str, Any]:
    with st.sidebar:
        st.header("检测控制台")
        dataset_choice = st.selectbox(
            "数据集选择",
            options=["demo_small", "demo_medium", "demo_large", "custom"],
            index=1,
        )
        run_clicked = st.button("运行检测", type="primary", use_container_width=True)

        default_paths = DATASET_PATHS.get(
            dataset_choice,
            {
                "policy": DEFAULT_POLICY_PATH,
                "logs": DEFAULT_LOG_PATH,
                "sensitive": DEFAULT_SENSITIVE_PATH,
            },
        )
        with st.expander("文件路径", expanded=False):
            if dataset_choice == "custom":
                policy_path = st.text_input(
                    "policy_declaration.yaml 路径",
                    value=st.session_state.get("custom_policy_path", DEFAULT_POLICY_PATH),
                    key="custom_policy_path",
                )
                log_path = st.text_input(
                    "actual_flow_logs.csv 路径",
                    value=st.session_state.get("custom_log_path", DEFAULT_LOG_PATH),
                    key="custom_log_path",
                )
                sensitive_path = st.text_input(
                    "sensitive_fields.json 路径",
                    value=st.session_state.get(
                        "custom_sensitive_path",
                        DEFAULT_SENSITIVE_PATH,
                    ),
                    key="custom_sensitive_path",
                )
            else:
                policy_path = default_paths["policy"]
                log_path = default_paths["logs"]
                sensitive_path = default_paths["sensitive"]
                st.text_input(
                    "policy_declaration.yaml 路径",
                    value=policy_path,
                    disabled=True,
                    key=f"{dataset_choice}_policy_path",
                )
                st.text_input(
                    "actual_flow_logs.csv 路径",
                    value=log_path,
                    disabled=True,
                    key=f"{dataset_choice}_log_path",
                )
                st.text_input(
                    "sensitive_fields.json 路径",
                    value=sensitive_path,
                    disabled=True,
                    key=f"{dataset_choice}_sensitive_path",
                )

        with st.expander("检测配置", expanded=True):
            enable_ml_anomaly = st.checkbox("启用机器学习异常检测", value=True)
            contamination = st.slider(
                "Isolation Forest contamination",
                min_value=0.05,
                max_value=0.4,
                value=0.15,
                step=0.05,
            )

        with st.expander("图谱过滤", expanded=False):
            graph_choice = st.radio(
                "图类型选择",
                options=list(GRAPH_OPTIONS.keys()),
                index=0,
            )
            selected_risk_levels = st.multiselect(
                "风险等级过滤",
                options=["high", "medium", "low"],
                default=["high", "medium"],
            )
            only_violation_edges = st.checkbox("只显示违规边", value=True)
            only_external_edges = st.checkbox("只显示外部传输边", value=False)
            top_k_edges = st.slider(
                "Top-K 高风险边",
                min_value=10,
                max_value=100,
                value=40,
                step=5,
            )

    return {
        "dataset_choice": dataset_choice,
        "policy_path": policy_path,
        "log_path": log_path,
        "sensitive_path": sensitive_path,
        "enable_ml_anomaly": enable_ml_anomaly,
        "contamination": contamination,
        "graph_choice": graph_choice,
        "selected_risk_levels": selected_risk_levels,
        "only_violation_edges": only_violation_edges,
        "only_external_edges": only_external_edges,
        "top_k_edges": top_k_edges,
        "run_clicked": run_clicked,
    }


st.title(PAGE_TITLE)
st.caption(PAGE_SUBTITLE)
st.write(PAGE_DESCRIPTION)

sidebar_config = render_sidebar()
dataset_choice = sidebar_config["dataset_choice"]
policy_path = sidebar_config["policy_path"]
log_path = sidebar_config["log_path"]
sensitive_path = sidebar_config["sensitive_path"]
enable_ml_anomaly = sidebar_config["enable_ml_anomaly"]
contamination = sidebar_config["contamination"]
graph_choice = sidebar_config["graph_choice"]
selected_risk_levels = sidebar_config["selected_risk_levels"]
only_violation_edges = sidebar_config["only_violation_edges"]
only_external_edges = sidebar_config["only_external_edges"]
top_k_edges = sidebar_config["top_k_edges"]
run_clicked = sidebar_config["run_clicked"]

if run_clicked:
    with st.spinner("正在执行数据流检测与图谱生成..."):
        try:
            st.session_state["flowguardgraph_result"] = run_detection(
                policy_path=policy_path,
                log_path=log_path,
                sensitive_path=sensitive_path,
                enable_ml_anomaly=enable_ml_anomaly,
                contamination=contamination,
            )
            st.session_state["flowguardgraph_error"] = None
            st.session_state["flowguardgraph_exception"] = None
            st.session_state["flowguardgraph_report_paths"] = None
        except Exception as exc:  # noqa: BLE001
            st.session_state["flowguardgraph_result"] = None
            st.session_state["flowguardgraph_error"] = str(exc)
            st.session_state["flowguardgraph_exception"] = exc

if st.session_state.get("flowguardgraph_error"):
    st.error(f"检测失败：{st.session_state['flowguardgraph_error']}")
    exception = st.session_state.get("flowguardgraph_exception")
    if exception is not None:
        st.exception(exception)

if st.session_state.get("flowguardgraph_result"):
    render_dashboard(
        st.session_state["flowguardgraph_result"],
        dataset_choice,
        graph_choice,
        selected_risk_levels,
        only_violation_edges,
        only_external_edges,
        top_k_edges,
    )
else:
    render_default_state(policy_path, log_path, sensitive_path, dataset_choice)
