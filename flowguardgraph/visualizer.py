from html import escape
from pathlib import Path
import re
from typing import Any

from pyvis.network import Network

from flowguardgraph.compliance_checker import check_compliance
from flowguardgraph.graph_builder import (
    build_policy_graph,
    build_risk_graph,
    build_runtime_graph,
)
from flowguardgraph.log_parser import load_flow_logs
from flowguardgraph.policy_loader import load_policy
from flowguardgraph.risk_analyzer import analyze_risks, load_sensitive_fields


def ensure_output_dir(output_dir: str = "outputs") -> str:
    path = Path(output_dir)
    path.mkdir(parents=True, exist_ok=True)
    return str(path)


def format_list_value(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, list):
        return ", ".join(str(item) for item in value)
    return str(value)


def truncate_list_for_tooltip(
    value: Any,
    max_items: int = 5,
    max_chars: int = 200,
) -> str:
    if value is None:
        return ""

    if isinstance(value, list):
        visible_items = [str(item) for item in value[:max_items]]
        if len(value) > max_items:
            visible_items.append("...")
        text = ", ".join(visible_items)
    else:
        text = str(value)

    if len(text) > max_chars:
        return text[: max(0, max_chars - 3)] + "..."
    return text


def build_node_tooltip(node_id: str, attrs: dict[str, Any]) -> str:
    label = attrs.get("label", node_id)
    node_type = attrs.get("node_type", "")
    return (
        f"node: {truncate_list_for_tooltip(node_id)}\n"
        f"type: {truncate_list_for_tooltip(node_type)}\n"
        f"label: {truncate_list_for_tooltip(label)}"
    )


def build_edge_tooltip(source: str, target: str, attrs: dict[str, Any]) -> str:
    tooltip_fields = [
        ("source", source),
        ("target", target),
        ("fields", attrs.get("fields")),
        ("purposes", attrs.get("purposes")),
        ("violation_types", attrs.get("violation_types")),
        ("delta_type", attrs.get("delta_type")),
        ("risk_level", attrs.get("risk_level")),
        ("max_risk_score", attrs.get("max_risk_score")),
        ("avg_risk_score", attrs.get("avg_risk_score")),
        ("event_count", attrs.get("event_count")),
        ("total_volume", attrs.get("total_volume")),
        ("is_allowed", attrs.get("is_allowed")),
        ("reasons", attrs.get("reasons")),
        ("risk_reasons", attrs.get("risk_reasons")),
    ]

    return "\n".join(
        f"{key}: {truncate_list_for_tooltip(value)}"
        for key, value in tooltip_fields
    )


def get_node_style(attrs: dict[str, Any]) -> dict[str, Any]:
    label = str(attrs.get("label", "")).lower()
    node_type = attrs.get("node_type", "internal")

    if "unknown_external" in label:
        return {"color": "#D62728", "shape": "diamond", "size": 30}
    if node_type == "external":
        return {"color": "#FF8C00", "shape": "triangle", "size": 28}
    return {"color": "#87CEEB", "shape": "dot", "size": 22}


def get_edge_style(attrs: dict[str, Any]) -> dict[str, Any]:
    delta_type = attrs.get("delta_type")
    risk_level = attrs.get("risk_level", "low")
    is_allowed = attrs.get("is_allowed", True)

    if delta_type == "high_risk_exfiltration":
        style = {"color": "#D62728", "width": 4, "dashes": True}
    elif delta_type == "external_unapproved":
        style = {"color": "#D62728", "width": 3, "dashes": True}
    elif delta_type == "purpose_mismatch":
        style = {"color": "#FF8C00", "width": 3, "dashes": True}
    elif delta_type == "sensitive_exfiltration":
        style = {"color": "#FF8C00", "width": 3, "dashes": True}
    elif delta_type == "mixed":
        style = {"color": "#D62728", "width": 4, "dashes": True}
    elif risk_level == "high":
        style = {"color": "#D62728", "width": 4, "dashes": True}
    elif risk_level == "medium":
        style = {"color": "#FF8C00", "width": 3, "dashes": True}
    elif risk_level == "declared":
        style = {"color": "#666666", "width": 2, "dashes": False}
    else:
        style = {"color": "#2CA02C", "width": 2, "dashes": False}

    if is_allowed is False:
        style["dashes"] = True

    return style


def visualize_graph(
    G,
    output_path: str = "outputs/data_flow_graph.html",
    height: str = "750px",
    width: str = "100%",
    notebook: bool = False,
    graph_title: str = "Data Flow Graph",
    graph_description: str = "",
    include_header: bool = True,
) -> str:
    output = Path(output_path)
    if output.parent != Path("."):
        ensure_output_dir(str(output.parent))

    network = Network(
        height=height,
        width=width,
        directed=True,
        notebook=notebook,
        cdn_resources="in_line",
    )

    for node_id, attrs in G.nodes(data=True):
        style = get_node_style(attrs)
        network.add_node(
            node_id,
            label=str(attrs.get("label", node_id)),
            title=build_node_tooltip(str(node_id), attrs),
            color=style["color"],
            shape=style["shape"],
            size=style["size"],
        )

    for source, target, attrs in G.edges(data=True):
        style = get_edge_style(attrs)
        network.add_edge(
            source,
            target,
            title=build_edge_tooltip(str(source), str(target), attrs),
            label=_build_edge_label(attrs),
            color=style["color"],
            width=style["width"],
            dashes=style["dashes"],
        )

    network.set_options(
        """
        {
          "physics": {
            "enabled": true,
            "solver": "forceAtlas2Based",
            "forceAtlas2Based": {
              "gravitationalConstant": -120,
              "centralGravity": 0.008,
              "springLength": 260,
              "springConstant": 0.06,
              "avoidOverlap": 1.0
            },
            "minVelocity": 0.75,
            "stabilization": {
              "enabled": true,
              "iterations": 220
            }
          },
          "interaction": {
            "hover": true,
            "tooltipDelay": 100,
            "navigationButtons": true,
            "keyboard": true
          }
        }
        """
    )
    network.write_html(str(output), notebook=notebook, open_browser=False)
    if include_header:
        _prepend_graph_header(
            output,
            graph_title=graph_title,
            graph_description=graph_description,
            num_nodes=G.number_of_nodes(),
            num_edges=G.number_of_edges(),
        )
    return str(output)


def visualize_policy_runtime_risk_graphs(
    policy_graph,
    runtime_graph,
    risk_graph,
    output_dir: str = "outputs",
    include_header: bool = True,
) -> dict[str, str]:
    output_root = Path(ensure_output_dir(output_dir))
    return {
        "policy": visualize_graph(
            policy_graph,
            str(output_root / "policy_graph.html"),
            graph_title="Policy Graph：声明允许的数据流图",
            graph_description="该图展示数据处理者声明允许的数据流路径，可作为合规检测的基准图。",
            include_header=include_header,
        ),
        "runtime": visualize_graph(
            runtime_graph,
            str(output_root / "runtime_graph.html"),
            graph_title="Runtime Graph：实际发生的数据流图",
            graph_description="该图展示日志中实际发生的数据流路径，用于与声明规则进行一致性比对。",
            include_header=include_header,
        ),
        "risk": visualize_graph(
            risk_graph,
            str(output_root / "risk_graph.html"),
            graph_title="Risk Graph：非计划数据外传风险图",
            graph_description="该图展示基于声明—行为一致性比对、敏感字段识别和风险评分得到的高风险数据外传路径。",
            include_header=include_header,
        ),
    }


def _build_edge_label(attrs: dict[str, Any]) -> str:
    graph_type = attrs.get("graph_type")
    risk_level = attrs.get("risk_level")
    delta_type = attrs.get("delta_type")

    if graph_type == "delta" or delta_type:
        if delta_type and attrs.get("max_risk_score") is not None:
            return f"{delta_type} | {float(attrs['max_risk_score']):.2f}"
        return str(delta_type or "delta")
    if graph_type == "policy" or risk_level == "declared":
        return "declared"
    if graph_type == "runtime":
        return f"events: {attrs.get('event_count', 0)}"
    if risk_level and attrs.get("max_risk_score") is not None:
        return f"{risk_level} | {float(attrs['max_risk_score']):.2f}"
    if risk_level:
        return str(risk_level)
    return ""


def _prepend_graph_header(
    output_path: Path,
    graph_title: str,
    graph_description: str,
    num_nodes: int,
    num_edges: int,
) -> None:
    html = output_path.read_text(encoding="utf-8")
    header = _build_graph_header_html(
        graph_title=graph_title,
        graph_description=graph_description,
        num_nodes=num_nodes,
        num_edges=num_edges,
    )
    html = re.sub(r"(<body[^>]*>)", rf"\1{header}", html, count=1, flags=re.IGNORECASE)
    output_path.write_text(html, encoding="utf-8")


def _build_graph_header_html(
    graph_title: str,
    graph_description: str,
    num_nodes: int,
    num_edges: int,
) -> str:
    return f"""
    <style>
      .flowguardgraph-header {{
        box-sizing: border-box;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
        padding: 18px 22px 12px;
        border-bottom: 1px solid #e6e8eb;
        background: #ffffff;
        color: #20242a;
      }}
      .flowguardgraph-header h1 {{
        margin: 0 0 8px;
        font-size: 24px;
        font-weight: 700;
        letter-spacing: 0;
      }}
      .flowguardgraph-header p {{
        margin: 0 0 10px;
        max-width: 980px;
        color: #4f5865;
        line-height: 1.5;
      }}
      .flowguardgraph-meta {{
        display: flex;
        gap: 14px;
        margin-bottom: 12px;
        font-size: 13px;
        color: #303742;
      }}
      .flowguardgraph-legend {{
        display: flex;
        flex-wrap: wrap;
        gap: 12px 18px;
        align-items: center;
        font-size: 13px;
        color: #303742;
      }}
      .flowguardgraph-legend strong {{
        margin-right: 4px;
      }}
      .legend-item {{
        display: inline-flex;
        align-items: center;
        gap: 6px;
        white-space: nowrap;
      }}
      .legend-node {{
        display: inline-block;
        width: 13px;
        height: 13px;
      }}
      .legend-dot {{
        border-radius: 50%;
        background: #87CEEB;
      }}
      .legend-triangle {{
        width: 0;
        height: 0;
        border-left: 8px solid transparent;
        border-right: 8px solid transparent;
        border-bottom: 14px solid #FF8C00;
      }}
      .legend-diamond {{
        background: #D62728;
        transform: rotate(45deg);
      }}
      .legend-edge {{
        width: 34px;
        border-top: 3px solid #2CA02C;
      }}
      .legend-edge-medium {{
        border-top-color: #FF8C00;
        border-top-style: dashed;
      }}
      .legend-edge-high {{
        border-top: 4px dashed #D62728;
      }}
      .legend-edge-declared {{
        border-top-color: #666666;
      }}
    </style>
    <section class="flowguardgraph-header">
      <h1>{escape(graph_title)}</h1>
      <p>{escape(graph_description)}</p>
      <div class="flowguardgraph-meta">
        <span>节点数：{num_nodes}</span>
        <span>边数：{num_edges}</span>
      </div>
      <div class="flowguardgraph-legend" aria-label="FlowGuardGraph Legend">
        <strong>节点：</strong>
        <span class="legend-item"><span class="legend-node legend-dot"></span>蓝色圆形：内部系统或内部数据资产</span>
        <span class="legend-item"><span class="legend-triangle"></span>橙色三角形：外部系统</span>
        <span class="legend-item"><span class="legend-node legend-diamond"></span>红色菱形：未知或高危外部系统</span>
        <strong>边：</strong>
        <span class="legend-item"><span class="legend-edge"></span>绿色实线：低风险或正常流动</span>
        <span class="legend-item"><span class="legend-edge legend-edge-medium"></span>橙色虚线：中风险或声明用途不一致</span>
        <span class="legend-item"><span class="legend-edge legend-edge-high"></span>红色粗虚线：高风险非计划外传</span>
        <span class="legend-item"><span class="legend-edge legend-edge-declared"></span>灰色实线：声明允许的数据流</span>
      </div>
    </section>
    """


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

    output_paths = visualize_policy_runtime_risk_graphs(
        build_policy_graph(policy),
        build_runtime_graph(events),
        build_risk_graph(risk_results),
    )

    print(f"policy graph HTML: {output_paths['policy']}")
    print(f"runtime graph HTML: {output_paths['runtime']}")
    print(f"risk graph HTML: {output_paths['risk']}")


if __name__ == "__main__":
    main()
