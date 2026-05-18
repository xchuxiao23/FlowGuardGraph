# 系统设计文档

## 1. 系统设计目标

FlowGuardGraph 的目标是构建一个面向数据安全治理场景的研究原型系统，用数据流图表示声明规则和实际行为，并通过一致性检测、敏感字段识别和风险评分发现非计划数据外传风险。

核心设计目标包括：

- 用结构化方式表达声明允许的数据流；
- 从日志中提取实际发生的数据流事件；
- 将声明规则和实际行为统一映射到图结构；
- 识别未声明字段、未声明外部目标和用途不一致行为；
- 对敏感字段和外部传输进行风险评分；
- 通过 Streamlit 和 PyVis 提供可交互的图谱监测界面。

## 2. 系统总体架构

系统流程如下：

```text
声明规则 → 实际日志 → 数据流图构建 → 一致性检测 → 敏感字段识别 → 风险评分 → 可视化预警
```

主要输入包括：

- `policy_declaration.yaml`：声明允许的数据流规则；
- `actual_flow_logs.csv`：实际数据流日志；
- `sensitive_fields.json`：敏感字段等级配置。

主要输出包括：

- 合规检测结果；
- 风险评分结果；
- Policy Graph、Runtime Graph、Risk Graph；
- Streamlit 前端中的指标、表格、统计图和交互式图谱。

## 3. 模块说明

### policy_loader

`policy_loader.py` 负责读取 YAML 声明规则，并使用 Pydantic 模型进行字段校验。

主要能力：

- 加载 `PolicyConfig`；
- 校验 `systems` 和 `allowed_flows`；
- 将声明规则展开为 `(source, target, field)` 索引。

### log_parser

`log_parser.py` 负责读取 CSV 实际数据流日志，并转换为结构化 `FlowEvent`。

主要能力：

- 校验必要日志字段；
- 将 `volume` 转换为整数；
- 判断目标系统是否为外部系统；
- 汇总日志来源、目标、字段和 volume。

### compliance_checker

`compliance_checker.py` 负责执行声明—行为一致性检测。

主要能力：

- 判断实际 `source-target-field` 是否已声明；
- 判断实际用途是否与声明用途一致；
- 输出 `ComplianceResult`；
- 统计违规类型，包括 `external_unapproved`、`unregistered_flow` 和 `purpose_mismatch`。

### risk_analyzer

`risk_analyzer.py` 负责读取敏感字段配置，并对每条合规检测结果计算风险分数。

主要能力：

- 加载敏感字段等级；
- 字段名大小写不敏感匹配；
- 按风险公式计算 `risk_score`；
- 输出 `RiskResult`；
- 汇总 high、medium、low 风险事件数量。

### graph_builder

`graph_builder.py` 负责构建三类 NetworkX 有向图。

主要能力：

- 构建 Policy Graph；
- 构建 Runtime Graph；
- 构建 Risk Graph；
- 聚合边上的字段、用途、违规类型、风险分数和事件数量；
- 导出图结构 JSON。

### visualizer

`visualizer.py` 负责将 NetworkX 图转换为 PyVis HTML 图。

主要能力：

- 设置节点样式和边样式；
- 生成节点与边 tooltip；
- 支持带标题图例的独立 HTML；
- 支持用于 Streamlit 嵌入的 compact HTML。

### app

`app.py` 是 Streamlit 前端入口。

主要能力：

- 通过侧边栏配置输入文件路径、图类型和风险过滤；
- 执行完整检测流程；
- 使用 session state 缓存检测结果；
- 通过三个 tab 展示图谱监测、风险事件和统计分析。

## 4. 三类图说明

### Policy Graph

Policy Graph 表示声明允许的数据流。

- 节点：声明中的 source 和 target；
- 边：声明允许的 source → target；
- 边属性：允许字段、声明用途、最大频率、是否允许外部传输。

### Runtime Graph

Runtime Graph 表示日志中实际发生的数据流。

- 节点：日志中的 source 和 target；
- 边：实际发生的 source → target；
- 边属性：实际字段、用途、动作、用户、事件数量和总 volume。

### Risk Graph

Risk Graph 表示带合规和风险信息的实际数据流。

- 节点：实际数据流涉及的数据资产和系统；
- 边：实际数据流路径；
- 边属性：违规类型、原因、风险原因、最大风险分数、平均风险分数、风险等级和合规状态。

## 5. 声明—行为一致性检测逻辑

检测逻辑按以下顺序执行：

1. 使用 `(source, target, field)` 查询声明规则索引；
2. 如果查不到规则，则判断为未声明数据流；
3. 如果目标为外部系统，则标记为 `external_unapproved`；
4. 如果目标不是外部系统，则标记为 `unregistered_flow`；
5. 如果查到规则但用途不一致，则标记为 `purpose_mismatch`；
6. 如果字段、目标和用途均一致，则判断为合规。

## 6. 风险评分逻辑

风险评分公式为：

```text
risk_score =
0.4 × policy_violation
+ 0.3 × sensitivity_score
+ 0.2 × external_target
+ 0.1 × purpose_mismatch
```

风险等级：

- `high`：`risk_score >= 0.75`
- `medium`：`risk_score >= 0.45`
- `low`：`risk_score < 0.45`

该评分方式强调未声明行为、敏感字段和外部传输的组合风险。

## 7. 可视化设计

可视化由 PyVis 和 Streamlit 共同完成：

- PyVis 负责交互式网络图；
- Streamlit 负责页面布局、指标、表格和统计图；
- 节点颜色区分内部系统、外部系统和未知高危外部系统；
- 边颜色和线型区分低风险、中风险、高风险和声明规则；
- tooltip 展示字段、用途、违规类型、原因和风险分数等细节。

## 8. 后续扩展方向

- 增加 SQL 数据流解析模块；
- 接入真实企业日志源；
- 增加频率阈值检测和时序异常检测；
- 增加更细粒度的敏感字段识别；
- 支持多租户和多系统数据资产建模；
- 增加告警导出、审计报告和追踪闭环；
- 引入图算法识别异常路径和高风险外部节点。
