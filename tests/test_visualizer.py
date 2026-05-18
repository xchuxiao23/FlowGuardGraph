from pathlib import Path

from flowguardgraph.compliance_checker import check_compliance
from flowguardgraph.graph_builder import build_risk_graph
from flowguardgraph.log_parser import load_flow_logs
from flowguardgraph.policy_loader import load_policy
from flowguardgraph.risk_analyzer import analyze_risks, load_sensitive_fields
from flowguardgraph.visualizer import (
    build_edge_tooltip,
    build_node_tooltip,
    format_list_value,
    get_edge_style,
    get_node_style,
    visualize_graph,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = PROJECT_ROOT / "examples" / "policy_declaration.yaml"
LOG_PATH = PROJECT_ROOT / "examples" / "actual_flow_logs.csv"
SENSITIVE_PATH = PROJECT_ROOT / "examples" / "sensitive_fields.json"


def build_example_risk_graph():
    policy = load_policy(str(POLICY_PATH))
    events = load_flow_logs(str(LOG_PATH))
    compliance_results = check_compliance(events, policy)
    sensitive_map = load_sensitive_fields(str(SENSITIVE_PATH))
    risk_results = analyze_risks(compliance_results, sensitive_map)
    return build_risk_graph(risk_results)


def test_format_list_value() -> None:
    assert format_list_value(["name", "age"]) == "name, age"
    assert format_list_value(None) == ""
    assert format_list_value("statistics") == "statistics"


def test_node_and_edge_tooltip() -> None:
    node_tooltip = build_node_tooltip(
        "external_crm",
        {"label": "external_crm", "node_type": "external"},
    )
    edge_tooltip = build_edge_tooltip(
        "internal_db.user_profile",
        "external_crm",
        {
            "fields": ["email"],
            "purposes": ["customer_service"],
            "risk_level": "medium",
        },
    )

    assert isinstance(node_tooltip, str)
    assert "external_crm" in node_tooltip
    assert isinstance(edge_tooltip, str)
    assert "internal_db.user_profile" in edge_tooltip
    assert "external_crm" in edge_tooltip
    assert "medium" in edge_tooltip


def test_get_node_style() -> None:
    internal_style = get_node_style(
        {"label": "analytics_service", "node_type": "internal"}
    )
    external_style = get_node_style({"label": "external_crm", "node_type": "external"})
    unknown_style = get_node_style(
        {"label": "unknown_external", "node_type": "external"}
    )

    assert internal_style["color"] != external_style["color"]
    assert internal_style == {"color": "#87CEEB", "shape": "dot", "size": 22}
    assert external_style == {"color": "#FF8C00", "shape": "triangle", "size": 28}
    assert unknown_style == {"color": "#D62728", "shape": "diamond", "size": 30}


def test_get_edge_style() -> None:
    high_style = get_edge_style({"risk_level": "high", "is_allowed": True})
    low_style = get_edge_style({"risk_level": "low", "is_allowed": True})
    medium_style = get_edge_style({"risk_level": "medium", "is_allowed": True})
    declared_style = get_edge_style({"risk_level": "declared", "is_allowed": True})
    violation_style = get_edge_style({"risk_level": "low", "is_allowed": False})

    assert high_style["width"] > low_style["width"]
    assert high_style["color"] == "#D62728"
    assert high_style["dashes"] is True
    assert medium_style["color"] == "#FF8C00"
    assert medium_style["dashes"] is True
    assert declared_style["color"] == "#666666"
    assert violation_style["dashes"] is True


def test_visualize_graph_output(tmp_path: Path) -> None:
    graph = build_example_risk_graph()
    output_path = tmp_path / "risk_graph.html"

    generated_path = visualize_graph(
        graph,
        str(output_path),
        graph_title="Risk Graph：非计划数据外传风险图",
        graph_description="测试图说明。",
    )
    content = Path(generated_path).read_text(encoding="utf-8").lower()

    assert Path(generated_path).exists()
    assert "html" in content
    assert "risk graph：非计划数据外传风险图".lower() in content
    assert "蓝色圆形：内部系统或内部数据资产" in content
    assert "红色粗虚线：高风险非计划外传" in content
    assert "high |" in content or "risk_level" in content
    assert (
        "external_partner" in content
        or "unknown_external" in content
        or "risk_level" in content
    )
