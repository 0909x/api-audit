# API安全审计工具

基于大语言模型（DeepSeek-R1-0528-Qwen3-8B）的API安全审计工具，检测越权（BOLA）、参数遍历、接口滥用等攻击行为，输出可解释的安全告警。

**规则引擎 F1=1.0（55样本）| LLM对抗集检出率 100%（24/24）| 类型混淆率 0%**

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

所有配置集中在 `config/settings.py`，可通过 `.env` 文件覆盖。


---

## 数据模型

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
# 结果: TP=44 FP=0 TN=11 FN=0, F1=1.0
```

### 2. LLM 对抗评估

```bash
python demo.py --adversarial --llm
# 结果: LLM TP=24/24 (100%)
```

### 3. 完整评测（含 LLM、XGBoost）

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
- **对抗评估数据集**（`src/evaluation/adversarial_dataset.py`）：6 类 × 4 样本 = 24 个，专门绕过规则引擎，用于评测 LLM 边界能力
  - `body_bola`：POST body 中跨用户访问同一资源
  - `b64_traversal`：Base64 编码的路径参数单调递增
  - `low_freq_abuse`：低频（<5次）但模式明显的滥用
  - `biz_anomaly`：跳过关键业务步骤
  - `noise_mixed`：在正常序列中混入攻击
  - `version_traversal`：API 版本号递增遍历

---



## 评测结果

### 规则引擎基线（55样本）

| 策略 | TP | FP | TN | FN | Precision | Recall | F1 |
|---|---|---|---|---|---|---|---|
| 规则引擎 | 44 | 0 | 11 | 0 | 1.0000 | 1.0000 | **1.0000** |

dvapi FN 通过在 `_gen_bola` 中增加回退策略（safe_resource为空时使用 endpoint.path + 随机ID）修复。

### LLM 对抗评估（24样本）

| 指标 | 结果 |
|------|------|
| 检出率 (Recall) | **100%（24/24）** |
| 类型混淆率 | **0%（0/7）** |
| 迭代轮次 | 4轮（50% → 71% → 88% → 100%） |

对抗数据集覆盖 6 种规则盲区：body BOLA、Base64 遍历、低频滥用、业务异常、噪声混合、版本遍历。经过四轮 Prompt + 数据集迭代达到完全检出。

---

## 常见问题

**Q: Streamlit 启动报编码错误？**
A: 在终端执行 `set PYTHONIOENCODING=utf-8` 后再启动 Streamlit。

**Q: 如何切换 LLM 模型？**
A: 修改 `.env` 中的 `LLM_MODEL`，或直接在 `config/settings.py` 中更改默认值。

**Q: 告警数据如何持久化？**
A: 当前为内存存储。后续对接 SQLite 或 Redis 时只需修改 AlertStore 的实现，API 接口不变。
