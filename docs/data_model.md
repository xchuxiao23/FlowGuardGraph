# 数据模型文档

## FlowPolicy

声明数据流规则模型，表示一条允许的数据流。

字段说明：

- `source: str`：数据来源，例如 `internal_db.user_profile`。
- `target: str`：数据目标，例如 `analytics_service`。
- `fields: list[str]`：允许传输的字段列表。
- `purpose: str`：声明用途。
- `max_frequency_per_minute: int`：每分钟最大允许传输频率。
- `allow_external: bool`：是否允许传输到外部系统。

## PolicyConfig

声明策略配置模型。

字段说明：

- `systems: list[str]`：声明中涉及的系统列表。
- `allowed_flows: list[FlowPolicy]`：允许的数据流规则列表。

## FlowEvent

实际数据流日志事件模型。

字段说明：

- `timestamp: str`：事件发生时间。
- `user: str`：触发数据流的用户或服务账号。
- `source: str`：实际数据来源。
- `target: str`：实际数据目标。
- `field: str`：实际传输字段。
- `action: str`：操作类型，例如 `transfer` 或 `export`。
- `purpose: str`：实际用途。
- `volume: int`：传输量或事件量。

## ComplianceResult

声明—行为一致性检测结果模型。

字段说明：

- `event: FlowEvent`：被检测的实际日志事件。
- `is_allowed: bool`：该事件是否符合声明规则。
- `violation_type: str`：违规类型，可能为 `none`、`external_unapproved`、`unregistered_flow` 或 `purpose_mismatch`。
- `reason: str`：中文检测原因说明。
- `expected_purpose: str | None`：声明用途。
- `actual_purpose: str | None`：实际用途。

## RiskResult

风险评分结果模型。

字段说明：

- `compliance_result: ComplianceResult`：对应的合规检测结果。
- `sensitivity_level: str`：字段敏感等级。
- `sensitivity_score: float`：字段敏感等级对应分数。
- `external_target: bool`：目标是否为外部系统。
- `policy_violation: bool`：是否违反声明规则。
- `purpose_mismatch: bool`：用途是否不一致。
- `risk_score: float`：综合风险分数。
- `risk_level: str`：风险等级，取值为 `high`、`medium` 或 `low`。
- `risk_reason: str`：中文风险原因说明。

## Graph Node

图节点表示数据资产、内部系统或外部系统。

常见属性：

- `id`：节点唯一标识，通常为系统名或数据资产名。
- `label`：节点显示名称。
- `node_type`：节点类型，`internal` 或 `external`。

节点类型判断规则：

- 节点名称包含 `external`、`partner`、`crm` 或 `unknown` 时视为外部节点；
- 其他节点视为内部节点。

## Graph Edge

图边表示从 source 到 target 的数据流。

Policy Graph 边属性：

- `fields`：声明允许字段列表。
- `purposes`：声明用途列表。
- `graph_type`：固定为 `policy`。
- `allow_external`：是否允许外部传输。
- `max_frequency_per_minute`：最大允许频率。
- `is_allowed`：固定为 `True`。
- `risk_level`：固定为 `declared`。
- `risk_score`：固定为 `0.0`。

Runtime Graph 边属性：

- `fields`：实际传输字段列表。
- `purposes`：实际用途列表。
- `actions`：操作类型列表。
- `users`：用户或服务账号列表。
- `total_volume`：总传输量。
- `event_count`：事件数量。
- `graph_type`：固定为 `runtime`。

Risk Graph 边属性：

- `fields`：实际字段列表。
- `purposes`：实际用途列表。
- `violation_types`：违规类型列表。
- `reasons`：合规检测原因列表。
- `risk_reasons`：风险原因列表。
- `max_risk_score`：该边上的最高风险分数。
- `avg_risk_score`：该边上的平均风险分数。
- `risk_level`：聚合后的风险等级。
- `high_risk_event_count`：高风险事件数量。
- `medium_risk_event_count`：中风险事件数量。
- `low_risk_event_count`：低风险事件数量。
- `event_count`：事件数量。
- `total_volume`：总传输量。
- `is_allowed`：该边是否全部合规。
- `graph_type`：固定为 `risk`。
