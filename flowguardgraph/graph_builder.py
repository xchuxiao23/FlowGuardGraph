import json
from pathlib import Path
from typing import Any

import networkx as nx

from flowguardgraph.compliance_checker import check_compliance
from flowguardgraph.log_parser import (
    FlowEvent,
    infer_external_target,
    load_flow_logs,
)
from flowguardgraph.policy_loader import PolicyConfig, load_policy
from flowguardgraph.risk_analyzer import (
    RiskResult,
    analyze_risks,
    load_sensitive_fields,
)


def get_node_type(node_name: str) -> str:
    return "external" if infer_external_target(node_name) else "internal"


def build_policy_graph(policy: PolicyConfig) -> nx.DiGraph:
    graph = nx.DiGraph()

    for flow in policy.allowed_flows:
        _ensure_node(graph, flow.source)
        _ensure_node(graph, flow.target)

        if not graph.has_edge(flow.source, flow.target):
            graph.add_edge(
                flow.source,
                flow.target,
                fields=[],
                purposes=[],
                graph_type="policy",
                allow_external=flow.allow_external,
                max_frequency_per_minute=flow.max_frequency_per_minute,
                is_allowed=True,
                risk_level="declared",
                risk_score=0.0,
            )

        edge = graph[flow.source][flow.target]
        _extend_unique(edge["fields"], flow.fields)
        _append_unique(edge["purposes"], flow.purpose)
        edge["allow_external"] = edge["allow_external"] or flow.allow_external
        edge["max_frequency_per_minute"] = max(
            edge["max_frequency_per_minute"],
            flow.max_frequency_per_minute,
        )

    return graph


def build_runtime_graph(events: list[FlowEvent]) -> nx.DiGraph:
    graph = nx.DiGraph()

    for event in events:
        _ensure_node(graph, event.source)
        _ensure_node(graph, event.target)

        if not graph.has_edge(event.source, event.target):
            graph.add_edge(
                event.source,
                event.target,
                fields=[],
                purposes=[],
                actions=[],
                users=[],
                total_volume=0,
                event_count=0,
                graph_type="runtime",
            )

        edge = graph[event.source][event.target]
        _append_unique(edge["fields"], event.field)
        _append_unique(edge["purposes"], event.purpose)
        _append_unique(edge["actions"], event.action)
        _append_unique(edge["users"], event.user)
        edge["total_volume"] += event.volume
        edge["event_count"] += 1

    return graph


def build_risk_graph(risk_results: list[RiskResult]) -> nx.DiGraph:
    graph = nx.DiGraph()

    for risk_result in risk_results:
        compliance_result = risk_result.compliance_result
        event = compliance_result.event

        _ensure_node(graph, event.source)
        _ensure_node(graph, event.target)

        if not graph.has_edge(event.source, event.target):
            graph.add_edge(
                event.source,
                event.target,
                fields=[],
                purposes=[],
                violation_types=[],
                reasons=[],
                risk_reasons=[],
                max_risk_score=0.0,
                avg_risk_score=0.0,
                risk_level="low",
                high_risk_event_count=0,
                medium_risk_event_count=0,
                low_risk_event_count=0,
                event_count=0,
                total_volume=0,
                is_allowed=True,
                graph_type="risk",
                _risk_score_total=0.0,
            )

        edge = graph[event.source][event.target]
        _append_unique(edge["fields"], event.field)
        _append_unique(edge["purposes"], event.purpose)
        _append_unique(edge["violation_types"], compliance_result.violation_type)
        _append_unique(edge["reasons"], compliance_result.reason)
        _append_unique(edge["risk_reasons"], risk_result.risk_reason)
        edge["max_risk_score"] = max(edge["max_risk_score"], risk_result.risk_score)
        edge["_risk_score_total"] += risk_result.risk_score
        edge["risk_level"] = _dominant_risk_level(
            edge["risk_level"],
            risk_result.risk_level,
        )
        edge[f"{risk_result.risk_level}_risk_event_count"] += 1
        edge["event_count"] += 1
        edge["total_volume"] += event.volume
        edge["is_allowed"] = edge["is_allowed"] and compliance_result.is_allowed

    for _, _, edge in graph.edges(data=True):
        edge["avg_risk_score"] = round(
            edge["_risk_score_total"] / edge["event_count"],
            4,
        )
        del edge["_risk_score_total"]

    return graph


def summarize_graph(graph: nx.DiGraph) -> dict[str, int]:
    edge_data = [data for _, _, data in graph.edges(data=True)]

    return {
        "num_nodes": graph.number_of_nodes(),
        "num_edges": graph.number_of_edges(),
        "num_internal_nodes": sum(
            1
            for _, data in graph.nodes(data=True)
            if data.get("node_type") == "internal"
        ),
        "num_external_nodes": sum(
            1
            for _, data in graph.nodes(data=True)
            if data.get("node_type") == "external"
        ),
        "num_high_risk_edges": sum(
            1 for data in edge_data if data.get("risk_level") == "high"
        ),
        "num_medium_risk_edges": sum(
            1 for data in edge_data if data.get("risk_level") == "medium"
        ),
        "num_low_risk_edges": sum(
            1 for data in edge_data if data.get("risk_level") == "low"
        ),
        "num_violation_edges": sum(
            1 for data in edge_data if data.get("is_allowed") is False
        ),
    }


def export_graph_to_json(graph: nx.DiGraph, output_path: str) -> str:
    path = Path(output_path)
    if path.parent != Path("."):
        path.parent.mkdir(parents=True, exist_ok=True)

    payload = {
        "nodes": [
            {"id": node, **_json_ready(attributes)}
            for node, attributes in graph.nodes(data=True)
        ],
        "edges": [
            {
                "source": source,
                "target": target,
                **_json_ready(attributes),
            }
            for source, target, attributes in graph.edges(data=True)
        ],
    }

    with path.open("w", encoding="utf-8") as file:
        json.dump(payload, file, ensure_ascii=False, indent=2)

    return str(path)


def _ensure_node(graph: nx.DiGraph, node_name: str) -> None:
    if graph.has_node(node_name):
        return

    graph.add_node(
        node_name,
        label=node_name,
        node_type=get_node_type(node_name),
    )


def _append_unique(values: list[Any], value: Any) -> None:
    if value not in values:
        values.append(value)


def _extend_unique(values: list[Any], new_values: list[Any]) -> None:
    for value in new_values:
        _append_unique(values, value)


def _dominant_risk_level(current_level: str, new_level: str) -> str:
    risk_rank = {"low": 0, "medium": 1, "high": 2}
    return (
        new_level
        if risk_rank.get(new_level, 0) > risk_rank.get(current_level, 0)
        else current_level
    )


def _json_ready(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _json_ready(inner_value) for key, inner_value in value.items()}
    if isinstance(value, list):
        return [_json_ready(inner_value) for inner_value in value]
    if isinstance(value, tuple):
        return [_json_ready(inner_value) for inner_value in value]
    return value


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

    policy_graph = build_policy_graph(policy)
    runtime_graph = build_runtime_graph(events)
    risk_graph = build_risk_graph(risk_results)

    print(f"Policy Graph: {summarize_graph(policy_graph)}")
    print(f"Runtime Graph: {summarize_graph(runtime_graph)}")
    print(f"Risk Graph: {summarize_graph(risk_graph)}")
    print("Risk Graph high risk edges:")
    for source, target, edge in risk_graph.edges(data=True):
        if edge.get("risk_level") == "high":
            print(
                "  "
                f"{source} -> {target}, "
                f"max_risk_score={edge['max_risk_score']}, "
                f"fields={edge['fields']}"
            )


if __name__ == "__main__":
    main()
