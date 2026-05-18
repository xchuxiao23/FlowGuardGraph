from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ValidationError


class FlowPolicy(BaseModel):
    source: str
    target: str
    fields: list[str]
    purpose: str
    max_frequency_per_minute: int
    allow_external: bool


class PolicyConfig(BaseModel):
    systems: list[str]
    allowed_flows: list[FlowPolicy]


AllowedFlowIndex = dict[tuple[str, str, str], dict[str, Any]]


def load_policy(path: str) -> PolicyConfig:
    policy_path = Path(path)
    if not policy_path.exists():
        raise FileNotFoundError(f"Policy file not found: {policy_path}")

    try:
        with policy_path.open("r", encoding="utf-8") as file:
            raw_policy = yaml.safe_load(file)
    except yaml.YAMLError as exc:
        raise ValueError(f"Invalid YAML in policy file {policy_path}: {exc}") from exc

    try:
        return PolicyConfig.model_validate(raw_policy)
    except ValidationError as exc:
        raise ValueError(f"Invalid policy schema in {policy_path}: {exc}") from exc


def build_allowed_flow_index(policy: PolicyConfig) -> AllowedFlowIndex:
    allowed_index: AllowedFlowIndex = {}

    for flow in policy.allowed_flows:
        for field in flow.fields:
            allowed_index[(flow.source, flow.target, field)] = {
                "purpose": flow.purpose,
                "max_frequency_per_minute": flow.max_frequency_per_minute,
                "allow_external": flow.allow_external,
            }

    return allowed_index


def get_allowed_policy(
    source: str,
    target: str,
    field: str,
    allowed_index: AllowedFlowIndex,
) -> dict[str, Any] | None:
    return allowed_index.get((source, target, field))


def main() -> None:
    project_root = Path(__file__).resolve().parents[1]
    policy_path = project_root / "examples" / "policy_declaration.yaml"
    policy = load_policy(str(policy_path))
    allowed_index = build_allowed_flow_index(policy)

    print(f"systems: {len(policy.systems)}")
    print(f"allowed_flows: {len(policy.allowed_flows)}")
    print(f"allowed_index: {len(allowed_index)}")
    print("first_3_allowed_index:")
    for key, value in list(allowed_index.items())[:3]:
        print(f"  {key}: {value}")


if __name__ == "__main__":
    main()
