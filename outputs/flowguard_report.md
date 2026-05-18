# FlowGuardGraph 检测报告

- 项目名称：FlowGuardGraph
- 数据集名称：demo_large
- 检测时间：2026-05-18 20:57:30

## 检测结果总览

| 指标 | 数值 |
| --- | --- |
| 总事件数 | 1000 |
| 违规事件数 | 116 |
| 高风险事件数 | 56 |
| 外部传输事件数 | 204 |
| ML 异常事件数 | 148 |
| Delta 边数量 | 54 |

## Top 10 高风险事件

| timestamp | source | target | field | violation_type | risk_score | hybrid_risk_score | risk_level | hybrid_risk_level |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 2026-05-18T10:50:29Z | internal_db.audit_log | unknown_external | auth_token | external_unapproved | 0.9 | 0.925 | high | high |
| 2026-05-18T10:49:05Z | internal_db.risk_control | unknown_external | password | external_unapproved | 0.9 | 0.9247 | high | high |
| 2026-05-18T10:52:14Z | internal_db.health_record | unknown_external | password | external_unapproved | 0.9 | 0.9247 | high | high |
| 2026-05-18T10:50:50Z | internal_db.user_profile | external_crm | phone | purpose_mismatch | 0.85 | 0.8349 | high | high |
| 2026-05-18T10:41:37Z | internal_db.location_trace | external_partner | face_id | external_unapproved | 0.84 | 0.8312 | high | high |
| 2026-05-18T10:48:37Z | internal_db.payment_info | external_partner | salary | external_unapproved | 0.84 | 0.8312 | high | high |
| 2026-05-18T10:50:43Z | internal_db.health_record | external_partner | bank_card | external_unapproved | 0.84 | 0.8312 | high | high |
| 2026-05-18T10:42:19Z | internal_db.customer_service | external_partner | credit_score | external_unapproved | 0.84 | 0.8256 | high | high |
| 2026-05-18T10:52:49Z | internal_db.audit_log | external_partner | salary | external_unapproved | 0.84 | 0.8256 | high | high |
| 2026-05-18T10:55:58Z | internal_db.audit_log | external_partner | bank_card | external_unapproved | 0.84 | 0.8256 | high | high |

## Top 10 高风险 source-target 路径

| source | target | fields | max_risk_score | avg_risk_score | event_count | violation_types |
| --- | --- | --- | --- | --- | --- | --- |
| internal_db.health_record | unknown_external | password | 0.9 | 0.9 | 1 | external_unapproved |
| internal_db.audit_log | unknown_external | auth_token, device_id, email | 0.9 | 0.8 | 3 | external_unapproved |
| internal_db.risk_control | unknown_external | device_id, password | 0.9 | 0.8 | 3 | external_unapproved |
| internal_db.risk_control | external_payment_gateway | amount, device_id | 0.85 | 0.41 | 15 | external_unapproved, none, purpose_mismatch |
| internal_db.user_profile | external_crm | email, phone | 0.85 | 0.3738 | 21 | none, purpose_mismatch |
| internal_db.order_info | external_payment_gateway | amount, order_id | 0.85 | 0.3278 | 18 | none, purpose_mismatch |
| internal_db.device_log | external_partner | salary | 0.84 | 0.84 | 1 | external_unapproved |
| internal_db.user_profile | external_partner | face_id | 0.84 | 0.84 | 1 | external_unapproved |
| internal_db.payment_info | external_partner | email, id_card, salary | 0.84 | 0.8271 | 7 | external_unapproved |
| internal_db.marketing_profile | external_partner | bank_card, face_id, phone, salary | 0.84 | 0.8175 | 4 | external_unapproved |

## 风险等级分布

| risk_level | count |
| --- | --- |
| high | 56 |
| medium | 60 |
| low | 884 |

## 违规类型分布

| violation_type | count |
| --- | --- |
| external_unapproved | 54 |
| purpose_mismatch | 18 |
| unregistered_flow | 44 |
| none | 884 |

## 简短结论

检测结果显示存在高风险数据流，建议优先排查未授权外部传输、敏感字段外传和未知外部目标。
