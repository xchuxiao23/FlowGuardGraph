import json
from pathlib import Path

from flowguardgraph.compliance_checker import check_compliance
from flowguardgraph.graph_builder import (
    build_policy_graph,
    build_risk_graph,
    build_runtime_graph,
    export_graph_to_json,
    get_node_type,
    summarize_graph,
)
from flowguardgraph.log_parser import load_flow_logs
from flowguardgraph.policy_loader import load_policy
from flowguardgraph.risk_analyzer import analyze_risks, load_sensitive_fields


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


def test_get_node_type() -> None:
    assert get_node_type("analytics_service") == "internal"
    assert get_node_type("external_crm") == "external"
    assert get_node_type("external_partner") == "external"
    assert get_node_type("unknown_external") == "external"


def test_build_policy_graph() -> None:
    policy = load_policy(str(POLICY_PATH))
    graph = build_policy_graph(policy)

    assert graph.number_of_nodes() > 0
    assert graph.number_of_edges() > 0
    assert graph.has_edge("internal_db.user_profile", "analytics_service")

    edge = graph["internal_db.user_profile"]["analytics_service"]
    assert "name" in edge["fields"]
    assert "age" in edge["fields"]


def test_build_runtime_graph() -> None:
    events = load_flow_logs(str(LOG_PATH))
    graph = build_runtime_graph(events)

    assert graph.number_of_nodes() > 0
    assert graph.number_of_edges() > 0
    assert sum(edge["event_count"] for _, _, edge in graph.edges(data=True)) == 35


def test_build_risk_graph() -> None:
    graph = build_example_risk_graph()

    assert graph.number_of_nodes() > 0
    assert graph.number_of_edges() > 0
    assert any(edge["risk_level"] == "high" for _, _, edge in graph.edges(data=True))
    assert any(edge["is_allowed"] is False for _, _, edge in graph.edges(data=True))


def test_summarize_graph() -> None:
    graph = build_example_risk_graph()
    summary = summarize_graph(graph)

    assert isinstance(summary, dict)
    assert summary["num_nodes"] > 0
    assert summary["num_edges"] > 0
    assert summary["num_high_risk_edges"] > 0
    assert summary["num_violation_edges"] > 0


def test_export_graph_to_json(tmp_path: Path) -> None:
    graph = build_example_risk_graph()
    output_path = tmp_path / "risk_graph.json"

    exported_path = export_graph_to_json(graph, str(output_path))
    payload = json.loads(Path(exported_path).read_text(encoding="utf-8"))

    assert "nodes" in payload
    assert "edges" in payload
    assert len(payload["nodes"]) > 0
    assert len(payload["edges"]) > 0
