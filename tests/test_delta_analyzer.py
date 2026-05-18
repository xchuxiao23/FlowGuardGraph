from pathlib import Path

import pandas as pd

from flowguardgraph.compliance_checker import check_compliance
from flowguardgraph.delta_analyzer import (
    build_delta_graph,
    get_delta_edges_table,
    summarize_delta_graph,
)
from flowguardgraph.log_parser import load_flow_logs
from flowguardgraph.policy_loader import load_policy
from flowguardgraph.risk_analyzer import analyze_risks, load_sensitive_fields


PROJECT_ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = PROJECT_ROOT / "examples" / "policy_declaration.yaml"
LOG_PATH = PROJECT_ROOT / "examples" / "actual_flow_logs.csv"
SENSITIVE_PATH = PROJECT_ROOT / "examples" / "sensitive_fields.json"


def build_example_delta_graph():
    policy = load_policy(str(POLICY_PATH))
    events = load_flow_logs(str(LOG_PATH))
    compliance_results = check_compliance(events, policy)
    sensitive_map = load_sensitive_fields(str(SENSITIVE_PATH))
    risk_results = analyze_risks(compliance_results, sensitive_map)
    return build_delta_graph(risk_results)


def test_build_delta_graph_from_examples() -> None:
    graph = build_example_delta_graph()

    assert graph.number_of_nodes() > 0
    assert graph.number_of_edges() > 0


def test_delta_graph_contains_high_or_external_delta_edge() -> None:
    graph = build_example_delta_graph()
    delta_types = {
        edge["delta_type"]
        for _, _, edge in graph.edges(data=True)
    }

    assert (
        "high_risk_exfiltration" in delta_types
        or "external_unapproved" in delta_types
    )


def test_get_delta_edges_table() -> None:
    graph = build_example_delta_graph()
    dataframe = get_delta_edges_table(graph)

    assert isinstance(dataframe, pd.DataFrame)
    assert not dataframe.empty
    assert {
        "source",
        "target",
        "fields",
        "delta_type",
        "max_risk_score",
        "reasons",
    }.issubset(dataframe.columns)


def test_summarize_delta_graph() -> None:
    graph = build_example_delta_graph()
    summary = summarize_delta_graph(graph)

    assert summary["num_delta_edges"] > 0
    assert summary["num_nodes"] > 0
    assert summary["num_edges"] > 0
