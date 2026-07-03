# API安全审计工具

基于大语言模型（DeepSeek-R1-0528-Qwen3-8B）的API安全审计工具，检测越权（BOLA）、参数遍历、接口滥用等攻击行为，输出可解释的安全告警。

---

## 环境准备

### 1. 创建 conda 环境

```bash
conda create -n api-audit python=3.13
conda activate api-audit
```

### 2. 安装依赖

```bash
# 推荐使用 uv（比 pip 快 10-20 倍）
pip install uv
uv pip install -e ".[dev,logwatch]"

# 如需 Streamlit 控制台
uv pip install streamlit
```

pyproject.toml 中已声明的核心依赖：

| 包 | 用途 |
|---|---|
| `fastapi`, `uvicorn` | 代理中间件 HTTP 服务器 |
| `httpx` | LLM API 调用 |
| `openai` | OpenAI 兼容 SDK |
| `pyyaml` | OpenAPI YAML 解析 |
| `pydantic`, `pydantic-settings` | 数据模型 + 配置 |
| `structlog` | 结构化日志 |
| `pytest`, `pytest-asyncio` | 测试 |
| `watchdog` | 日志文件监听（可选） |

### 3. 配置

所有配置集中在 `config/settings.py`，可通过 `.env` 文件覆盖。当前已内嵌测试用 API Key：

```ini
# .env
SILICONFLOW_API_KEY=sk-yxbgyidxbppxmvofcxncyoiurivwvoqhrranssqsjzdenywt
LLM_MODEL=deepseek-ai/DeepSeek-R1-0528-Qwen3-8B
LOG_LEVEL=INFO
```

---

## 数据模型（前端关注）

### Alert（告警）

位于 `src/engine/alert.py`。这是前端控制台的核心展示对象：

```python
class Alert(BaseModel):
    alert_id: str           # "ALT-20260703-001"
    timestamp: str          # "2026-07-03T22:17:48+08:00"
    status: str             # "preliminary" | "confirmed" | "dismissed"
    severity: str           # "critical" | "high" | "medium" | "info"
    anomaly_type: str       # "bola" | "traversal" | "abuse" | "normal"
    confidence: float       # 0.0 ~ 1.0
    session_id: str         # 关联会话ID
    source_ip: str          # 源IP
    affected_endpoints: list[str]  # 受影响端点列表
    explanation: AlertExplanation   # 可解释信息
    raw_features: RawFeatures       # 原始特征
    raw_llm_output: str             # LLM原始输出

class AlertExplanation(BaseModel):
    summary: str                    # 告警摘要（1-2句话）
    chain_of_thought: str           # LLM思维链（推理过程）
    key_indicators: list[str]       # 关键指标清单
    risk_assessment: str            # 风险评估
    recommendation: str             # 处置建议

class RawFeatures(BaseModel):
    request_count: int              # 请求总量
    time_window_sec: float          # 时间窗口（秒）
    param_entropy: float            # 参数熵值
    not_found_ratio: float          # 4xx错误占比
    param_pattern: str              # 参数遍历模式
```

### severity 映射

| anomaly_type | severity |
|---|---|
| `bola` | `critical` |
| `traversal` | `high` |
| `abuse` | `medium` |
| `normal` | `info` |

### anomaly_type 中文标签

```python
ALERT_TYPE_LABELS = {
    "bola": "越权访问 (BOLA)",
    "traversal": "参数遍历攻击",
    "abuse": "接口滥用",
    "normal": "正常",
}
```

---

## 数据流

```
请求日志 → ChainBuilder → RuleEngine → process_request()
                                            │
                          ┌──────────────────┘
                          ▼
              generate_alert(llm_data, status="preliminary")
                          │
                          ▼
                     AlertStore.add(alert)
                          │
              LLM backstop worker (异步, 可选)
                          │
              upgrade_alert() → status="confirmed"
                          │
                  Streamlit 控制台 ← get_all() / count()
```

### 告警生命周期

1. **规则引擎触发** → 生成 `status="preliminary"` 告警，置信度 0.75
2. **LLM 异步兜底** → 若 LLM 确认异常，调用 `upgrade_alert()` 升级为 `confirmed`，更新思维链+推理
3. **重复会话去重** → 同一 session_id + anomaly_type 不重复生成

---

## AlertStore API

位于 `src/engine/alert_store.py`。所有方法线程安全，前端开发可直接在 Streamlit 中实例化使用：

```python
store = AlertStore(max_alerts=10000, retention_hours=24)

store.add(alert)                                          # 添加告警
store.get_all(limit=100, offset=0)                        # 分页获取（按时间倒序）
store.get_by_id("ALT-20260703-001")                       # 按ID查询
store.get_by_session_id("vampi_0000_abuse")               # 按会话查询
store.get_by_severity("critical", limit=50)               # 按严重级别筛选
store.get_recent(minutes=60)                              # 最近N分钟
store.count()                                             # 统计
# 返回: {"total": 42, "by_severity": {"critical": 10, ...},
#        "by_type": {"bola": 8, ...}, "by_status": {"preliminary": 3, ...}}

# 暂态管理
store.get_preliminary_by_session_id(session_id)           # 获取未确认告警
store.has_confirmed_alert(session_id, anomaly_type)       # 去重检查
store.upgrade_alert(alert_id, llm_result)                 # 升级为 confirmed
```

---

## 运行方式

### 1. 端到端评测（规则引擎）

```bash
# conda env 下
python demo.py
# 结果: TP=43 FP=0 TN=11 FN=1, F1=0.9885
```

### 2. 完整评测（含 LLM、XGBoost）

```bash
python scripts/run_evaluation.py
python scripts/run_evaluation.py --synthetic   # 使用合成数据集
python scripts/run_evaluation.py --include-xgboost
```

### 3. 代理模式（开发中）

```bash
# 待实现
python scripts/run_proxy.py
```

---

## 数据集

- **12 个真实 OpenAPI 规范** 位于 `data/`（dvapi, dvws, vapi, vampi, capital, RESTaurant, crAPI, memos, OWASP Juice Shop 等）
- **每个规范生成 5 种样本**：normal / bola / traversal / abuse / mixed
- 共 55 个样本（11 个 ≥3 端点的规范 × 5 类型）

---

## 前端开发任务（Streamlit 控制台）

目标文件：`src/console/streamlit_app.py`（尚未创建）

### 建议的功能面板

1. **告警概览仪表板**
   - 告警总数、各 severity 分布（柱状图/饼图）
   - 实时告警流（最近 N 条）
   - 按时间轴展示告警密度

2. **告警详情页**
   - 展示单条告警完整信息：summary / chain_of_thought / key_indicators / risk_assessment / recommendation
   - 原始特征：request_count, time_window, param_entropy, not_found_ratio
   - 受影响的端点列表

3. **数据过滤与搜索**
   - 按 severity（critical/high/medium/info）
   - 按 anomaly_type（bola/traversal/abuse）
   - 按 status（preliminary/confirmed/dismissed）
   - 按时间范围
   - 按 session_id 搜索

4. **告警管理操作**
   - 确认/忽略/关闭告警（更新 status）
   - 导出告警列表

### 数据对接方式

```python
import streamlit as st
from src.engine.alert_store import AlertStore
from src.engine.risk_scorer import compute_risk_score

# 初始化 store（模块级缓存，避免多页重建）
if "alert_store" not in st.session_state:
    st.session_state.alert_store = AlertStore()

store = st.session_state.alert_store

# 获取统计数据
stats = store.count()        # → {"total": ..., "by_severity": {...}, "by_type": {...}, "by_status": {...}}
alerts = store.get_all(limit=100)

# 遍历告警
for alert in alerts:
    risk_score = compute_risk_score(alert)
    st.write(f"{alert.alert_id} | {alert.anomaly_type} | {alert.severity} | {alert.confidence}")
    st.write(alert.explanation.summary)
    st.write(alert.explanation.recommendation)
```

### 注意事项

- 请尽量避免在界面中出现 Windows 终端无法显示的 Unicode 字符（emoji 等），如需图形提示请使用颜色、图标组件
- AlertStore 当前是内存存储（重启丢失），如需持久化可后续对接 SQLite

---

## 项目结构（前端相关部分）

```
src/
├── engine/
│   ├── alert.py              # Alert, AlertExplanation, RawFeatures ← ★ 核心数据模型
│   ├── alert_store.py        # AlertStore ← ★ 数据访问层
│   ├── risk_scorer.py        # compute_risk_score() ← ★ 风险评分
│   ├── pipeline.py           # AuditPipeline（规则+LLM流水线）
│   ├── explanation.py        # generate_alert() 生成告警
│   └── rule_engine.py        # 规则引擎
├── console/
│   └── streamlit_app.py      # ← 待开发的 Streamlit 控制台
└── ingestion/
    └── models.py             # RequestRecord 请求记录
```

---

## 评测结果（当前基线）

| 策略 | TP | FP | TN | FN | Precision | Recall | F1 |
|---|---|---|---|---|---|---|---|
| 规则引擎 | 43 | 0 | 11 | 1 | 1.0000 | 0.9773 | **0.9885** |

唯一 FN：dvapi.yaml 无路径参数 → BOLA 样本缺少资源 ID 参数 → 规则引擎无法检测。

---

## 常见问题

**Q: Streamlit 启动报编码错误？**
A: 在终端执行 `set PYTHONIOENCODING=utf-8` 后再启动 Streamlit。

**Q: 如何切换 LLM 模型？**
A: 修改 `.env` 中的 `LLM_MODEL`，或直接在 `config/settings.py` 中更改默认值。

**Q: 告警数据如何持久化？**
A: 当前为内存存储。后续对接 SQLite 或 Redis 时只需修改 AlertStore 的实现，API 接口不变。
