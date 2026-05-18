import argparse
import csv
import json
import random
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import yaml


INTERNAL_DATA_ASSETS = [
    "internal_db.user_profile",
    "internal_db.order_info",
    "internal_db.payment_info",
    "internal_db.health_record",
    "internal_db.device_log",
    "internal_db.location_trace",
    "internal_db.marketing_profile",
    "internal_db.risk_control",
    "internal_db.audit_log",
    "internal_db.customer_service",
]

INTERNAL_SERVICES = [
    "analytics_service",
    "risk_engine",
    "recommendation_service",
    "reporting_service",
    "fraud_detection_service",
    "customer_service_platform",
    "data_warehouse",
    "feature_platform",
]

EXTERNAL_SYSTEMS = [
    "external_crm",
    "external_ad_platform",
    "external_partner",
    "external_payment_gateway",
    "third_party_analytics",
    "unknown_external",
    "shadow_api",
]

SENSITIVE_FIELDS_BY_LEVEL = {
    "low": ["name", "age", "gender", "order_id", "product_id"],
    "medium": ["email", "phone", "address", "device_id", "amount", "location"],
    "high": [
        "id_card",
        "bank_card",
        "credit_score",
        "medical_record",
        "face_id",
        "salary",
    ],
    "critical": ["password", "private_key", "auth_token"],
}

ASSET_FIELDS = {
    "internal_db.user_profile": [
        "name",
        "age",
        "gender",
        "email",
        "phone",
        "address",
        "id_card",
        "password",
    ],
    "internal_db.order_info": ["order_id", "product_id", "amount", "address"],
    "internal_db.payment_info": ["order_id", "amount", "bank_card", "auth_token"],
    "internal_db.health_record": ["name", "age", "medical_record", "id_card"],
    "internal_db.device_log": ["device_id", "location", "auth_token"],
    "internal_db.location_trace": ["device_id", "location", "phone"],
    "internal_db.marketing_profile": ["name", "age", "gender", "email", "phone"],
    "internal_db.risk_control": ["credit_score", "device_id", "amount", "face_id"],
    "internal_db.audit_log": ["device_id", "auth_token", "private_key"],
    "internal_db.customer_service": ["name", "email", "phone", "order_id"],
}

PURPOSES = [
    "statistics",
    "business_analysis",
    "risk_control",
    "recommendation",
    "reporting",
    "fraud_detection",
    "customer_service",
    "feature_engineering",
]

ANOMALY_TYPES = [
    "external_unapproved",
    "purpose_mismatch",
    "sensitive_exfiltration",
    "critical_field_leakage",
    "frequency_anomaly",
    "volume_spike",
    "unknown_target",
    "low_and_slow_exfiltration",
    "partner_overreach",
]

LOG_COLUMNS = [
    "timestamp",
    "user",
    "source",
    "target",
    "field",
    "action",
    "purpose",
    "volume",
]

GROUND_TRUTH_COLUMNS = [
    "event_id",
    "timestamp",
    "source",
    "target",
    "field",
    "anomaly_type",
    "expected_risk_level",
    "reason",
]


def generate_policy(output_dir: str, seed: int = 42) -> str:
    output_root = _ensure_output_dir(output_dir)
    rules = _build_policy_rules(random.Random(seed))
    policy = {
        "systems": INTERNAL_DATA_ASSETS + INTERNAL_SERVICES + EXTERNAL_SYSTEMS,
        "allowed_flows": rules,
    }
    output_path = output_root / "policy_declaration.yaml"
    with output_path.open("w", encoding="utf-8") as file:
        yaml.safe_dump(policy, file, allow_unicode=True, sort_keys=False)
    return str(output_path)


def generate_flow_logs(
    output_dir: str,
    num_events: int = 300,
    anomaly_ratio: float = 0.18,
    seed: int = 42,
) -> str:
    output_root = _ensure_output_dir(output_dir)
    rows, _ = _generate_flow_rows(num_events, anomaly_ratio, seed)
    output_path = output_root / "actual_flow_logs.csv"
    _write_csv(output_path, LOG_COLUMNS, rows)
    return str(output_path)


def generate_sensitive_fields(output_dir: str) -> str:
    output_root = _ensure_output_dir(output_dir)
    sensitive_map = {
        field: level
        for level, fields in SENSITIVE_FIELDS_BY_LEVEL.items()
        for field in fields
    }
    output_path = output_root / "sensitive_fields.json"
    with output_path.open("w", encoding="utf-8") as file:
        json.dump(sensitive_map, file, ensure_ascii=False, indent=2)
    return str(output_path)


def generate_demo_sql(output_dir: str) -> str:
    output_root = _ensure_output_dir(output_dir)
    sql = """INSERT INTO analytics_service.user_statistics
SELECT name, age, gender FROM internal_db.user_profile;

INSERT INTO risk_engine.payment_risk_features
SELECT order_id, amount, device_id FROM internal_db.payment_info;

INSERT INTO recommendation_service.behavior_features
SELECT product_id, device_id FROM internal_db.device_log;

INSERT INTO external_crm.customer_contact
SELECT email, phone FROM internal_db.customer_service;

INSERT INTO external_partner.sensitive_export
SELECT id_card, bank_card, medical_record FROM internal_db.user_profile;

INSERT INTO unknown_external.credential_leak
SELECT password, private_key, auth_token FROM internal_db.audit_log;
"""
    output_path = output_root / "demo_sql.sql"
    output_path.write_text(sql, encoding="utf-8")
    return str(output_path)


def generate_ground_truth(
    output_dir: str,
    anomaly_records: list[dict],
) -> str:
    output_root = _ensure_output_dir(output_dir)
    output_path = output_root / "ground_truth_anomalies.csv"
    _write_csv(output_path, GROUND_TRUTH_COLUMNS, anomaly_records)
    return str(output_path)


def generate_demo_dataset(
    output_dir: str,
    num_events: int,
    anomaly_ratio: float,
    seed: int = 42,
) -> dict[str, str]:
    output_root = _ensure_output_dir(output_dir)
    policy_path = generate_policy(str(output_root), seed=seed)
    log_rows, anomaly_records = _generate_flow_rows(num_events, anomaly_ratio, seed)
    logs_path = output_root / "actual_flow_logs.csv"
    _write_csv(logs_path, LOG_COLUMNS, log_rows)
    sensitive_fields_path = generate_sensitive_fields(str(output_root))
    demo_sql_path = generate_demo_sql(str(output_root))
    ground_truth_path = generate_ground_truth(str(output_root), anomaly_records)

    return {
        "policy": policy_path,
        "logs": str(logs_path),
        "sensitive_fields": sensitive_fields_path,
        "demo_sql": demo_sql_path,
        "ground_truth": ground_truth_path,
    }


def _build_policy_rules(rng: random.Random) -> list[dict[str, Any]]:
    rules: list[dict[str, Any]] = []

    internal_targets = [
        "analytics_service",
        "risk_engine",
        "recommendation_service",
        "reporting_service",
        "fraud_detection_service",
        "data_warehouse",
        "feature_platform",
    ]
    external_allowed = {
        "external_crm": ["email", "phone", "order_id"],
        "external_payment_gateway": ["order_id", "amount"],
        "third_party_analytics": ["age", "gender", "product_id"],
        "external_ad_platform": ["age", "gender", "product_id"],
    }

    for asset in INTERNAL_DATA_ASSETS:
        allowed_fields = _low_medium_fields(asset)
        rng.shuffle(allowed_fields)
        for target in rng.sample(internal_targets, k=min(4, len(internal_targets))):
            field_count = rng.randint(1, min(4, len(allowed_fields)))
            rules.append(
                {
                    "source": asset,
                    "target": target,
                    "fields": allowed_fields[:field_count],
                    "purpose": _target_to_purpose(target),
                    "max_frequency_per_minute": rng.choice([10, 20, 30, 50]),
                    "allow_external": False,
                }
            )

    for target, candidate_fields in external_allowed.items():
        for asset in rng.sample(INTERNAL_DATA_ASSETS, k=5):
            fields = [
                field
                for field in candidate_fields
                if field in ASSET_FIELDS.get(asset, [])
                and _sensitivity_level(field) in {"low", "medium"}
            ]
            if not fields:
                continue
            rules.append(
                {
                    "source": asset,
                    "target": target,
                    "fields": fields[:2],
                    "purpose": "customer_service"
                    if target == "external_crm"
                    else "business_integration",
                    "max_frequency_per_minute": rng.choice([3, 5, 8]),
                    "allow_external": True,
                }
            )

    return rules


def _generate_flow_rows(
    num_events: int,
    anomaly_ratio: float,
    seed: int,
) -> tuple[list[dict], list[dict]]:
    rng = random.Random(seed)
    policy_rules = _build_policy_rules(random.Random(seed))
    normal_count = max(0, num_events - round(num_events * anomaly_ratio))
    anomaly_count = num_events - normal_count
    base_time = datetime(2026, 5, 18, 9, 0, 0)

    rows: list[dict] = []
    anomaly_records: list[dict] = []

    for index in range(normal_count):
        rule = rng.choice(policy_rules)
        field = rng.choice(rule["fields"])
        rows.append(
            {
                "timestamp": _format_timestamp(base_time, index),
                "user": _normal_user(rng),
                "source": rule["source"],
                "target": rule["target"],
                "field": field,
                "action": rng.choice(["transfer", "sync", "query"]),
                "purpose": rule["purpose"],
                "volume": rng.randint(1, 12),
            }
        )

    for offset in range(anomaly_count):
        event_id = normal_count + offset + 1
        anomaly_type = ANOMALY_TYPES[offset % len(ANOMALY_TYPES)]
        row, ground_truth = _generate_anomaly_row(
            rng,
            base_time,
            event_id,
            anomaly_type,
            policy_rules,
        )
        rows.append(row)
        anomaly_records.append(ground_truth)

    rng.shuffle(rows)
    for event_id, row in enumerate(rows, start=1):
        row["event_id"] = event_id

    anomaly_by_key = {
        (
            record["timestamp"],
            record["source"],
            record["target"],
            record["field"],
            record["anomaly_type"],
        ): record
        for record in anomaly_records
    }
    normalized_anomalies = []
    for row in rows:
        for key, record in anomaly_by_key.items():
            timestamp, source, target, field, _ = key
            if (
                row["timestamp"] == timestamp
                and row["source"] == source
                and row["target"] == target
                and row["field"] == field
            ):
                normalized = dict(record)
                normalized["event_id"] = row["event_id"]
                normalized_anomalies.append(normalized)
                break

    for row in rows:
        row.pop("event_id", None)

    return rows, normalized_anomalies


def _generate_anomaly_row(
    rng: random.Random,
    base_time: datetime,
    event_id: int,
    anomaly_type: str,
    policy_rules: list[dict],
) -> tuple[dict, dict]:
    timestamp = _format_timestamp(base_time, event_id)
    source = rng.choice(INTERNAL_DATA_ASSETS)

    if anomaly_type == "purpose_mismatch":
        rule = rng.choice(policy_rules)
        field = rng.choice(rule["fields"])
        source = rule["source"]
        target = rule["target"]
        purpose = _different_purpose(rule["purpose"], rng)
        expected_risk = "medium"
        reason = "实际用途与声明用途不一致。"
    elif anomaly_type == "critical_field_leakage":
        field = rng.choice(SENSITIVE_FIELDS_BY_LEVEL["critical"])
        target = rng.choice(["unknown_external", "shadow_api"])
        purpose = "unknown"
        expected_risk = "high"
        reason = "critical 字段流向未知或影子外部接口。"
    elif anomaly_type == "sensitive_exfiltration":
        field = rng.choice(SENSITIVE_FIELDS_BY_LEVEL["high"])
        target = rng.choice(["external_partner", "third_party_analytics"])
        purpose = "partner_sync"
        expected_risk = "high"
        reason = "高敏字段发生外部传输。"
    elif anomaly_type == "frequency_anomaly":
        rule = rng.choice(policy_rules)
        source = rule["source"]
        target = rule["target"]
        field = rng.choice(rule["fields"])
        purpose = rule["purpose"]
        expected_risk = "medium"
        reason = "短时间内同类字段传输频率异常。"
    elif anomaly_type == "volume_spike":
        rule = rng.choice(policy_rules)
        source = rule["source"]
        target = rule["target"]
        field = rng.choice(rule["fields"])
        purpose = rule["purpose"]
        expected_risk = "medium"
        reason = "单次传输 volume 明显高于正常水平。"
    elif anomaly_type == "unknown_target":
        field = rng.choice(_fields_for_asset(source))
        target = rng.choice(["unknown_external", "shadow_api"])
        purpose = "unknown"
        expected_risk = "high"
        reason = "数据流向未知外部目标。"
    elif anomaly_type == "low_and_slow_exfiltration":
        field = rng.choice(["email", "phone", "device_id", "location"])
        target = rng.choice(["external_partner", "third_party_analytics"])
        purpose = "background_sync"
        expected_risk = "medium"
        reason = "中敏字段以低速方式持续外传。"
    elif anomaly_type == "partner_overreach":
        field = rng.choice(["id_card", "bank_card", "credit_score", "salary"])
        target = "external_partner"
        purpose = "partner_sync"
        expected_risk = "high"
        reason = "合作方接收超出声明范围的敏感字段。"
    else:
        field = rng.choice(["email", "phone", "address", "device_id"])
        target = rng.choice(EXTERNAL_SYSTEMS)
        purpose = "unauthorized_export"
        expected_risk = "high"
        reason = "未声明字段或目标发生外部传输。"

    volume = (
        rng.randint(80, 180)
        if anomaly_type == "volume_spike"
        else rng.randint(1, 8)
    )
    row = {
        "timestamp": timestamp,
        "user": _anomaly_user(rng),
        "source": source,
        "target": target,
        "field": field,
        "action": rng.choice(["transfer", "export", "sync"]),
        "purpose": purpose,
        "volume": volume,
    }
    ground_truth = {
        "event_id": event_id,
        "timestamp": timestamp,
        "source": source,
        "target": target,
        "field": field,
        "anomaly_type": anomaly_type,
        "expected_risk_level": expected_risk,
        "reason": reason,
    }
    return row, ground_truth


def _ensure_output_dir(output_dir: str) -> Path:
    path = Path(output_dir)
    path.mkdir(parents=True, exist_ok=True)
    return path


def _write_csv(path: Path, columns: list[str], rows: list[dict]) -> None:
    with path.open("w", encoding="utf-8", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=columns)
        writer.writeheader()
        for row in rows:
            writer.writerow({column: row.get(column, "") for column in columns})


def _format_timestamp(base_time: datetime, index: int) -> str:
    return (base_time + timedelta(seconds=index * 7)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _normal_user(rng: random.Random) -> str:
    return rng.choice(
        [
            "analyst",
            "service_bot",
            "risk_job",
            "report_job",
            "feature_job",
            "sync_worker",
        ]
    ) + f"_{rng.randint(1, 30):02d}"


def _anomaly_user(rng: random.Random) -> str:
    return rng.choice(
        ["export_job", "unknown_job", "bulk_sync", "shadow_worker", "partner_job"]
    ) + f"_{rng.randint(1, 12):02d}"


def _target_to_purpose(target: str) -> str:
    mapping = {
        "analytics_service": "statistics",
        "risk_engine": "risk_control",
        "recommendation_service": "recommendation",
        "reporting_service": "reporting",
        "fraud_detection_service": "fraud_detection",
        "data_warehouse": "business_analysis",
        "feature_platform": "feature_engineering",
    }
    return mapping.get(target, "business_analysis")


def _different_purpose(current_purpose: str, rng: random.Random) -> str:
    candidates = [purpose for purpose in PURPOSES if purpose != current_purpose]
    return rng.choice(candidates)


def _fields_for_asset(asset: str) -> list[str]:
    return ASSET_FIELDS.get(asset, ["email", "phone", "amount"])


def _low_medium_fields(asset: str) -> list[str]:
    return [
        field
        for field in _fields_for_asset(asset)
        if _sensitivity_level(field) in {"low", "medium"}
    ] or ["name", "age"]


def _sensitivity_level(field: str) -> str:
    for level, fields in SENSITIVE_FIELDS_BY_LEVEL.items():
        if field in fields:
            return level
    return "unknown"


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate FlowGuardGraph demo data.")
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--num-events", type=int, default=300)
    parser.add_argument("--anomaly-ratio", type=float, default=0.18)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    paths = generate_demo_dataset(
        output_dir=args.output_dir,
        num_events=args.num_events,
        anomaly_ratio=args.anomaly_ratio,
        seed=args.seed,
    )
    for name, path in paths.items():
        print(f"{name}: {path}")


if __name__ == "__main__":
    main()
