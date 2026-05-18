from typing import Any

import networkx as nx
import pandas as pd

from flowguardgraph.graph_builder import get_node_type
from flowguardgraph.risk_analyzer import RiskResult


DeltaEdge = dict[str, Any]

RISK_LEVEL_RANK = {"low": 0, "medium": 1, "high": 2}
SENSITIVE_EXFILTRATION_LEVELS = {"medium", "high", "critical"}


def build_delta_graph(risk_results: list[RiskResult]) -> nx.DiGraph:
    graph = nx.DiGraph()

    for risk_result in risk_results:
        compliance_result = risk_result.compliance_result
        event = compliance_result.event

        if not _is_delta_event(risk_result):
            continue

        _ensure_node(graph, event.source)
        _ensure_node(graph, event.target)

        if not graph.has_edge(event.source, event.target):
            graph.add_edge(
                event.source,
                event.target,
                fields=[],
                violation_types=[],
                reasons=[],
                risk_reasons=[],
                risk_scores=[],
                max_risk_score=0.0,
                risk_level="low",
                delta_type="",
                delta_types=[],
                event_count=0,
                total_volume=0,
                is_allowed=True,
                graph_type="delta",
            )

        edge = graph[event.source][event.target]
        _append_unique(edge["fields"], event.field)
        _append_unique(edge["violation_types"], compliance_result.violation_type)
        _append_unique(edge["reasons"], compliance_result.reason)
        _append_unique(edge["risk_reasons"], risk_result.risk_reason)
        _append_unique(edge["delta_types"], _classify_delta_type(risk_result))
        edge["risk_scores"].append(risk_result.risk_score)
        edge["max_risk_score"] = max(edge["max_risk_score"], risk_result.risk_score)
        edge["risk_level"] = _dominant_risk_level(
            edge["risk_level"],
            risk_result.risk_level,
        )
        edge["event_count"] += 1
        edge["total_volume"] += event.volume
        edge["is_allowed"] = edge["is_allowed"] and compliance_result.is_allowed

    for _, _, edge in graph.edges(data=True):
        edge["delta_type"] = _aggregate_delta_type(edge["delta_types"])

    return graph


def summarize_delta_graph(graph: nx.DiGraph) -> dict[str, int]:
    edge_data = [data for _, _, data in graph.edges(data=True)]

    return {
        "num_nodes": graph.number_of_nodes(),
        "num_edges": graph.number_of_edges(),
        "num_delta_edges": graph.number_of_edges(),
        "num_external_unapproved_edges": sum(
            1 for data in edge_data if "external_unapproved" in data["violation_types"]
        ),
        "num_purpose_mismatch_edges": sum(
            1 for data in edge_data if "purpose_mismatch" in data["violation_types"]
        ),
        "num_high_risk_edges": sum(
            1
            for data in edge_data
            if data["risk_level"] == "high"
            or data["delta_type"] == "high_risk_exfiltration"
        ),
    }


def get_delta_edges_table(graph: nx.DiGraph) -> pd.DataFrame:
    rows = []
    for source, target, edge in graph.edges(data=True):
        rows.append(
            {
                "source": source,
                "target": target,
                "fields": _format_list(edge.get("fields", [])),
                "violation_types": _format_list(edge.get("violation_types", [])),
                "delta_type": edge.get("delta_type", ""),
                "risk_level": edge.get("risk_level", ""),
                "max_risk_score": edge.get("max_risk_score", 0.0),
                "reasons": " | ".join(edge.get("reasons", [])),
            }
        )

    dataframe = pd.DataFrame(
        rows,
        columns=[
            "source",
            "target",
            "fields",
            "violation_types",
            "delta_type",
            "risk_level",
            "max_risk_score",
            "reasons",
        ],
    )
    if not dataframe.empty:
        dataframe = dataframe.sort_values(
            by=["max_risk_score", "source", "target"],
            ascending=[False, True, True],
        )
    return dataframe


def _is_delta_event(risk_result: RiskResult) -> bool:
    return risk_result.policy_violation or risk_result.risk_level in {"medium", "high"}


def _classify_delta_type(risk_result: RiskResult) -> str:
    compliance_result = risk_result.compliance_result

    if risk_result.risk_level == "high":
        return "high_risk_exfiltration"
    if compliance_result.violation_type == "external_unapproved":
        return "external_unapproved"
    if compliance_result.violation_type == "purpose_mismatch":
        return "purpose_mismatch"
    if (
        risk_result.external_target
        and risk_result.sensitivity_level in SENSITIVE_EXFILTRATION_LEVELS
    ):
        return "sensitive_exfiltration"
    return compliance_result.violation_type


def _aggregate_delta_type(delta_types: list[str]) -> str:
    normalized_delta_types = [delta_type for delta_type in delta_types if delta_type]
    if not normalized_delta_types:
        return "mixed"
    if len(set(normalized_delta_types)) > 1:
        return "mixed"
    return normalized_delta_types[0]


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


def _dominant_risk_level(current_level: str, new_level: str) -> str:
    return (
        new_level
        if RISK_LEVEL_RANK.get(new_level, 0) > RISK_LEVEL_RANK.get(current_level, 0)
        else current_level
    )


def _format_list(values: list[Any]) -> str:
    return ", ".join(str(value) for value in values)
