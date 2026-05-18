from pathlib import Path

from flowguardgraph.log_parser import (
    FlowEvent,
    infer_external_target,
    load_flow_logs,
    logs_to_dataframe,
    summarize_flow_events,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]
LOG_PATH = PROJECT_ROOT / "examples" / "actual_flow_logs.csv"


def test_load_flow_logs_success() -> None:
    events = load_flow_logs(str(LOG_PATH))

    assert len(events) == 35
    assert all(isinstance(event, FlowEvent) for event in events)


def test_logs_to_dataframe() -> None:
    events = load_flow_logs(str(LOG_PATH))
    dataframe = logs_to_dataframe(events)

    assert len(dataframe) == len(events)
    assert {
        "timestamp",
        "source",
        "target",
        "field",
        "purpose",
        "volume",
    }.issubset(dataframe.columns)


def test_infer_external_target() -> None:
    assert infer_external_target("external_partner") is True
    assert infer_external_target("external_crm") is True
    assert infer_external_target("unknown_external") is True
    assert infer_external_target("analytics_service") is False


def test_summarize_flow_events() -> None:
    events = load_flow_logs(str(LOG_PATH))
    summary = summarize_flow_events(events)

    assert summary["total_events"] == 35
    assert summary["external_events"] > 0
    assert summary["unique_sources"] > 0
    assert summary["unique_targets"] > 0
