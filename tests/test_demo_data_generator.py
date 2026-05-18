from pathlib import Path

import pandas as pd

from flowguardgraph.demo_data_generator import generate_demo_dataset
from flowguardgraph.log_parser import load_flow_logs
from flowguardgraph.policy_loader import load_policy


def _generate_dataset(tmp_path: Path, num_events: int = 120) -> dict[str, str]:
    return generate_demo_dataset(
        output_dir=str(tmp_path / "demo_medium"),
        num_events=num_events,
        anomaly_ratio=0.2,
        seed=42,
    )


def test_generate_demo_dataset_creates_files(tmp_path):
    paths = _generate_dataset(tmp_path)

    assert Path(paths["policy"]).exists()
    assert Path(paths["logs"]).exists()
    assert Path(paths["sensitive_fields"]).exists()
    assert Path(paths["demo_sql"]).exists()
    assert Path(paths["ground_truth"]).exists()


def test_generated_flow_log_row_count(tmp_path):
    paths = _generate_dataset(tmp_path, num_events=120)
    logs = pd.read_csv(paths["logs"])

    assert len(logs) == 120


def test_ground_truth_is_not_empty(tmp_path):
    paths = _generate_dataset(tmp_path, num_events=120)
    ground_truth = pd.read_csv(paths["ground_truth"])

    assert not ground_truth.empty
    assert {
        "event_id",
        "timestamp",
        "source",
        "target",
        "field",
        "anomaly_type",
        "expected_risk_level",
        "reason",
    }.issubset(ground_truth.columns)


def test_generated_policy_can_be_loaded(tmp_path):
    paths = _generate_dataset(tmp_path)
    policy = load_policy(paths["policy"])

    assert len(policy.systems) > 0
    assert len(policy.allowed_flows) > 0


def test_generated_logs_can_be_loaded(tmp_path):
    paths = _generate_dataset(tmp_path, num_events=120)
    events = load_flow_logs(paths["logs"])

    assert len(events) == 120


def test_generated_dataset_is_reproducible(tmp_path):
    first_paths = generate_demo_dataset(
        output_dir=str(tmp_path / "first"),
        num_events=80,
        anomaly_ratio=0.2,
        seed=42,
    )
    second_paths = generate_demo_dataset(
        output_dir=str(tmp_path / "second"),
        num_events=80,
        anomaly_ratio=0.2,
        seed=42,
    )

    assert Path(first_paths["logs"]).read_text(encoding="utf-8") == Path(
        second_paths["logs"]
    ).read_text(encoding="utf-8")
