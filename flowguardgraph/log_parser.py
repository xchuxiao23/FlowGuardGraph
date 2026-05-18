from pathlib import Path

import pandas as pd
from pydantic import BaseModel, ValidationError


FLOW_EVENT_COLUMNS = [
    "timestamp",
    "user",
    "source",
    "target",
    "field",
    "action",
    "purpose",
    "volume",
]

EXTERNAL_TARGET_KEYWORDS = ("external", "partner", "crm", "unknown")


class FlowEvent(BaseModel):
    timestamp: str
    user: str
    source: str
    target: str
    field: str
    action: str
    purpose: str
    volume: int


def load_flow_logs(path: str) -> list[FlowEvent]:
    log_path = Path(path)
    if not log_path.exists():
        raise FileNotFoundError(f"Flow log file not found: {log_path}")

    dataframe = pd.read_csv(log_path)
    missing_columns = [
        column for column in FLOW_EVENT_COLUMNS if column not in dataframe.columns
    ]
    if missing_columns:
        missing = ", ".join(missing_columns)
        raise ValueError(f"Flow log file {log_path} is missing columns: {missing}")

    events: list[FlowEvent] = []
    for row_number, row in enumerate(dataframe[FLOW_EVENT_COLUMNS].to_dict("records"), start=2):
        try:
            row["volume"] = int(row["volume"])
            events.append(FlowEvent.model_validate(row))
        except (TypeError, ValueError, ValidationError) as exc:
            raise ValueError(
                f"Invalid flow log row {row_number} in {log_path}: {exc}"
            ) from exc

    return events


def logs_to_dataframe(events: list[FlowEvent]) -> pd.DataFrame:
    rows = [event.model_dump() for event in events]
    return pd.DataFrame(rows, columns=FLOW_EVENT_COLUMNS)


def infer_external_target(target: str) -> bool:
    normalized_target = target.lower()
    return any(keyword in normalized_target for keyword in EXTERNAL_TARGET_KEYWORDS)


def summarize_flow_events(events: list[FlowEvent]) -> dict[str, int]:
    return {
        "total_events": len(events),
        "unique_sources": len({event.source for event in events}),
        "unique_targets": len({event.target for event in events}),
        "external_events": sum(
            1 for event in events if infer_external_target(event.target)
        ),
        "unique_fields": len({event.field for event in events}),
        "total_volume": sum(event.volume for event in events),
    }


def main() -> None:
    project_root = Path(__file__).resolve().parents[1]
    log_path = project_root / "examples" / "actual_flow_logs.csv"
    events = load_flow_logs(str(log_path))
    summary = summarize_flow_events(events)

    print(f"total_events: {summary['total_events']}")
    print(f"unique_sources: {summary['unique_sources']}")
    print(f"unique_targets: {summary['unique_targets']}")
    print(f"external_events: {summary['external_events']}")
    print(f"unique_fields: {summary['unique_fields']}")
    print(f"total_volume: {summary['total_volume']}")
    print("first_5_events:")
    for event in events[:5]:
        print(f"  {event.model_dump()}")


if __name__ == "__main__":
    main()
