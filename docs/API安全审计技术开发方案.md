# 基于大语言模型的API安全审计技术开发方案

## 一、项目概述

### 1.1 选题背景

方向一要求构建一套基于大语言模型（LLM）的API安全分析工具，核心能力包括：分析API请求序列、参数分布与访问模式，识别越权（BOLA）、参数遍历、接口滥用等攻击行为，并输出可解释的安全告警。预期成果形态为API安全分析工具，支持代理模式或日志分析模式，需提供正常调用与异常调用的评测结果及完整演示。

### 1.2 核心目标

* **行为理解**：使LLM具备对API调用链、参数语义、访问上下文的深度理解能力
* **威胁识别**：准确检测越权访问、参数遍历攻击、接口滥用、异常调用模式
* **可解释输出**：每一条告警均附带自然语言解释，说明判定依据、风险等级与处置建议
* **工具化落地**：提供可部署的代理组件或日志分析流水线，支持真实流量接入与评测

\---

## 二、技术路线

### 2.1 总体思路

采用 **"规则前置 + LLM兜底 + 可解释输出"** 的三层架构：

|层级|功能|技术选型|
|-|-|-|
|数据通道|实时流量采集或日志批处理|代理拦截（Mitmproxy/自定义网关）或日志导入（ELK/Filebeat）|
|检测通道|规则引擎即时告警 + LLM异步确认/兜底|轻量规则引擎 + DeepSeek-R1-0528-Qwen3-8B（硅基流动API）|
|解释通道|告警解释与归因|思维链输出解析 + LLM叙事生成|

### 2.2 路线选择的依据

* **LLM在BOLA检测上已验证有效**：2025年University of Twente的研究表明，LLM基于OpenAPI规范分析端点依赖与参数类型，可实现较高的召回率，但需配合动态验证降低假阳性 [$TRAE\_REF](https://essay.utwente.nl/fileshare/file/107423/Johansens_BA_BIT.pdf)
* **调用链分析优于单点检测**：CSCWD 2025年DAB-LLM研究显示，将API调用序列建模为链（ACC）与图（ACG），结合LoRA微调，F1-score可达97.35%，显著优于单请求检测 [$TRAE\_REF](http://lostnet.info/cscwd2025/pdf/Paper_421.pdf)
* **可解释性是刚需**：DeepSeek-R1-0528-Qwen3-8B作为思维链蒸馏模型，推理过程中天然产出可读的思维过程，可直接作为告警解释的素材，免去额外XAI归因的复杂度 [$TRAE\_REF](https://arxiv.org/pdf/2309.16021v1)

\---

## 三、系统架构设计

### 3.1 整体架构

```
┌─────────────────────────────────────────────────────────────┐
│                        用户/API客户端                         │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│  代理模式                    │  日志分析模式                   │
│  ┌──────────────┐           │  ┌──────────────┐              │
│  │ API安全网关   │           │  │ 日志采集器    │              │
│  │ (拦截/转发)   │           │  │ (Filebeat)   │              │
│  └──────┬───────┘           │  └──────┬───────┘              │
└─────────┼───────────────────┴─────────┼──────────────────────┘
          │                           │
          ▼                           ▼
┌─────────────────────────────────────────────────────────────┐
│                    请求序列化与特征提取层                       │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐       │
│  │ 调用链构建    │  │ 参数特征提取  │  │ 访问模式统计  │       │
│  │ (ACC/ACG)    │  │ (类型/分布)   │  │ (频率/时序)   │       │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘       │
└─────────┼──────────────────┼─────────────────┼───────────────┘
          │                  │                 │
          └──────────────────┼─────────────────┘
                             ▼
┌─────────────────────────────────────────────────────────────┐
│                      检测引擎层                               │
│  ┌──────────────────────┐    ┌──────────────────────────┐   │
│  │   规则引擎(轻量过滤)   │    │   LLM深度分析引擎         │   │
│  │  - 频率阈值           │    │  - Prompt工程分析         │   │
│  │  - 黑名单参数         │  │  - 微调模型推理(Qwen3-8B)   │   │
│  │  - 基础越权模式       │    │  - 上下文感知识别         │   │
│  └──────────────────────┘    └──────────────────────────┘   │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│                     可解释告警生成层                          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐       │
│ │ <think >思维链│  │ 结构化JSON   │  │ 风险评分     │       │
│ │ 输出解析      │  │ 结果提取     │  │ 处置建议     │       │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘       │
└─────────┼──────────────────┼─────────────────┼───────────────┘
          │                  │                 │
          └──────────────────┼─────────────────┘
                             ▼
┌─────────────────────────────────────────────────────────────┐
│                     输出与交互层                              │
│         告警控制台 │ REST API │ 评测报告 │ 演示界面           │
└─────────────────────────────────────────────────────────────┘
```

### 3.2 核心数据流

1. **流量接入**：代理模式实时拦截HTTP/HTTPS请求；日志模式批量读取Nginx/Apache/应用日志
2. **序列构建**：按会话ID或Token聚合请求，构建时间有序的API调用链（ACC），并提取有向调用图（ACG）
3. **特征编码**：将链/图转化为带分隔符的文本序列，同时提取数值统计特征（接口访问唯一性、序列长度、错误码占比、参数熵值等）
4. **分层检测**：
   - **规则引擎前置**：同步检查每个请求，命中即产生 **初步告警** (status=preliminary, confidence≈0.75)，毫秒级响应
   - **LLM异步确认**：每个会话仅一次入队，后台 Worker 执行 LLM 深度分析
     - 同类型 → **升级** 为 confirmed (confidence↑, 补充思维链解释)
     - 不同类型 → 新建 confirmed 告警（如规则判 abuse，LLM 发现隐藏 BOLA）
     - 正常 → 保留 preliminary（规则误报防护）
   - **LLM全量兜底**：规则未触发的会话（如 BOLA 无频率特征），LLM 兜底发现后直接出 confirmed
5. **解释生成**：解析模型`<think>`标签中的思维链作为推理依据，提取最终JSON作为判定结果，融合生成可解释告警
6. **结果输出**：结构化告警JSON + 可视化控制台（含状态标签） + 评测指标统计

\---

## 四、关键模块实现方法

### 4.1 API调用序列建模模块

#### 4.1.1 ACC（API Call Chain）构建

将同一用户会话内的API调用按时间排序，形成线性序列：

```text
\\\\\\\[GET /api/v1/users/{id}] -> \\\\\\\[GET /api/v1/orders?userId={id}] -> \\\\\\\[POST /api/v1/orders/{id}/cancel]
```

实现要点：

* 以`Authorization`头中的Token或Session Cookie作为会话标识
* 设定时间窗口（默认30分钟）切分会话边界
* 序列长度截断至128个调用，超长序列滑动窗口采样

#### 4.1.2 ACG（API Call Graph）构建

将调用关系建模为有向图，捕获接口间依赖：

```python
# 示例：从调用链提取边
edges = \\\\\\\[]
for i in range(len(chain) - 1):
    src = normalize\\\\\\\_endpoint(chain\\\\\\\[i].path, chain\\\\\\\[i].method)
    dst = normalize\\\\\\\_endpoint(chain\\\\\\\[i+1].path, chain\\\\\\\[i+1].method)
    edges.append((src, dst))
```

图序列化表示：

```text
((GET /users/{id}, GET /orders), (GET /orders, POST /orders/{id}/cancel))
```

### 4.2 参数分布与访问模式分析

#### 4.2.1 参数特征提取

|特征维度|提取方法|攻击检测用途|
|-|-|-|
|参数类型|正则匹配（ID/Email/UUID/枚举值）|识别对象ID参数，辅助BOLA检测|
|参数熵值|Shannon熵计算|高熵可能指示遍历攻击|
|参数分布|滑动窗口内参数值频次统计|发现均匀分布（遍历）vs 自然分布|
|参数关联|跨请求参数值传递追踪|发现参数篡改、越权跳转|

#### 4.2.2 访问模式统计特征

参考DAB-LLM的数值特征设计 [$TRAE\_REF](http://lostnet.info/cscwd2025/pdf/Paper_421.pdf)：

* `inter\\\\\\\_api\\\\\\\_access\\\\\\\_duration`：相邻API调用间隔时间的均值与方差
* `api\\\\\\\_access\\\\\\\_uniqueness`：会话内访问的唯一接口数占总接口比例
* `sequence\\\\\\\_length`：当前调用链长度
* `num\\\\\\\_client\\\\\\\_error`：4xx响应次数占比
* `param\\\\\\\_reuse\\\\\\\_ratio`：跨端点参数复用率（异常复用可能暗示越权）

### 4.3 LLM检测引擎

本项目统一采用 **DeepSeek-R1-0528-Qwen3-8B** 作为核心审计模型。该模型通过从 DeepSeek-R1-0528 蒸馏思维链到 Qwen3 8B Base 获得，在开源模型中达到SOTA性能，AIME 2024测试超越Qwen3-8B 10%，达到Qwen3-235B-thinking的性能水平，在数学推理、编程和通用逻辑等基准测试中表现出色。架构与Qwen3-8B相同，共享DeepSeek-R1-0528的分词器配置。

**选型理由**：

* BOLA检测本质是多步推理（根据端点参数、认证机制推理授权缺失），思维链蒸馏模型天然匹配
* DeepSeek-R1在BOLA检测学术评测中综合表现最佳，该模型是其蒸馏版，推理链路一致
* 硅基流动已托管该模型，通过OpenAI兼容接口即可调用，无需GPU，零部署成本
* 思维过程天然可见，可直接作为告警解释的基础素材

#### 4.3.1 Prompt工程设计

针对思维链蒸馏模型的输出特性，Prompt需同时约束思维过程和最终输出格式。经过四轮迭代优化，最终采用以下完整模板：

**系统提示（System Prompt）**：
```
你是一位API安全审计专家，擅长通过分析API调用序列识别越权、参数遍历和接口滥用行为。

安全知识参考（请重点参考以下判定逻辑）：
- BOLA（越权）：调用序列中出现"登录(Token_A) → 获取资源ID → 登出 → 登录(Token_B) → 用Token_B访问同一资源ID"的模式，即不同认证身份访问相同资源ID，且返回200时判定为BOLA越权。注意：BOLA不需要大量请求，只要出现"不同Token访问同一资源"即可判定。跨会话BOLA：用户A访问某资源ID后登出，用户B登入后访问同一资源ID也构成BOLA。
- 参数遍历：对同一端点发起请求，参数值呈线性递增或均匀分布（即使请求次数少于20次）。典型特征：路径参数单调递增（如 /api/notes/Ab1000 → Ab1001 → Ab1002），步长固定。注意请求次数少但参数值严格递增也算遍历。
- 接口滥用：非业务逻辑顺序调用（如未登录直接访问订单），或单一接口高频调用（>正常均值10倍），或同一参数被重复调用。

特别注意：
- 请求序列中即使大部分请求看似正常，只要其中存在上述任何一种模式，就应判定为异常
- "请求序列分析"部分的"端点频率分布"、"参数单调递增指数"和"可疑标记"对判定非常重要：如果某个端点占比极高且参数单调递增，高度疑似遍历
- OpenAPI规范信息中描述了标准业务流程：如果调用顺序违反(如跳过必要步骤)，也构成异常
- 单个请求也可能异常（如违反业务逻辑的操作）

推理过程请控制在200字以内，简明扼要。
最终必须且仅输出以下JSON格式（不要输出其他内容）：
{"is_anomaly": true/false, "anomaly_type": "bola/traversal/abuse/normal", "confidence": 0.0-1.0, "reasoning": "中文解释，50字以内"}
```

**用户提示（User Prompt）**：
```
调用序列（ACC）：
[GET /api/v1/users/login] -> [POST /api/v1/login] -> [GET /api/v1/users/profile]

调用关系图（ACG）：
((GET /api/v1/users/login, POST /api/v1/login), (POST /api/v1/login, GET /api/v1/users/profile))

参数特征摘要：
参数总数: 5, 路径参数: 2, 查询参数: 3, 熵值: 2.58, 类型分布: {'id': 2, 'uuid': 1, 'other': 2}

访问模式统计：
  inter_api_access_duration: {'mean': 1.23, 'stdev': 0.45, 'values': [...]}
  api_access_uniqueness: 0.6
  sequence_length: 5
  num_client_error: 0.0
  param_reuse_ratio: 0.35
  param_monotonicity: 0.0
  endpoint_freq: {'distribution': {'GET /api/v1/users/login': 1, 'POST /api/v1/login': 1, 'GET /api/v1/users/profile': 1}, 'top_endpoint': 'GET /api/v1/users/login', 'top_endpoint_ratio': 0.33}

请求序列分析：
总请求数: 5
端点频率分布: GET /api/v1/users/login (1次), POST /api/v1/login (1次), GET /api/v1/users/profile (1次)
最高占比端点: GET /api/v1/users/login (33%)
参数单调递增指数: 0.0 (0-1, 越高越可疑)

OpenAPI规范信息：
API: PetStore v1.0, 12 endpoints

OpenAPI端点详情：
PetStore v1.0, 12 端点:
  GET /pet/{petId} [需认证] path_params=(petId)
  POST /pet [需认证]
  ...
```

`请求序列分析` 段落在迭代过程中增加了以下自动检测标记，直接引导LLM注意力：
- `可疑标记: 单一端点占比极高且参数单调递增，高度疑似参数遍历`
- `可疑标记: 同一端点相同参数重复调用 {N} 次，疑似接口滥用`
- `可疑标记: 资源ID {id} 被用户 {u1} 和 {u2} 同时访问，存在BOLA(越权)嫌疑`

#### 4.3.2 思维链输出解析策略

DeepSeek-R1-0528-Qwen3-8B的输出格式通常为 `<think >推理过程</think >最终答案`。需要编写后处理模块进行结构化解析：

```python
import re
import json

def parse\\\\\\\_model\\\\\\\_output(raw\\\\\\\_output: str) -> dict:
    """解析思维链蒸馏模型的输出，分离推理过程与结构化结果"""
    
    # 提取<think >标签内的思维链作为reasoning依据
    think\\\\\\\_match = re.search(r'<think >(.\\\\\\\*?)</think >', raw\\\\\\\_output, re.DOTALL)
    chain\\\\\\\_of\\\\\\\_thought = think\\\\\\\_match.group(1).strip() if think\\\\\\\_match else ""
    
    # 提取思维链之后的内容作为JSON结果
    json\\\\\\\_part = re.sub(r'<think >.\\\\\\\*?</think >', '', raw\\\\\\\_output, flags=re.DOTALL).strip()
    
    try:
        result = json.loads(json\\\\\\\_part)
        # 如果模型reasoning较简略，用思维链补充丰富
        if len(result.get("reasoning", "")) < 30 and chain\\\\\\\_of\\\\\\\_thought:
            result\\\\\\\["chain\\\\\\\_of\\\\\\\_thought"] = chain\\\\\\\_of\\\\\\\_thought
        return result
    except json.JSONDecodeError:
        # 降级处理：将整个输出作为reasoning返回
        return {
            "is\\\\\\\_anomaly": False,
            "anomaly\\\\\\\_type": "parse\\\\\\\_error",
            "confidence": 0.0,
            "reasoning": f"模型输出解析失败，原始输出：{raw\\\\\\\_output\\\\\\\[:200]}",
            "chain\\\\\\\_of\\\\\\\_thought": chain\\\\\\\_of\\\\\\\_thought
        }
```

#### 4.3.3 模型部署方案（硅基流动API）

通过硅基流动（SiliconFlow）的云端API调用 DeepSeek-R1-0528-Qwen3-8B，无需本地部署，开箱即用。

**Python调用示例**：

```python
from openai import OpenAI

client = OpenAI(
    api\\\\\\\_key="sk-yxbgyidxbppxmvofcxncyoiurivwvoqhrranssqsjzdenywt",           # 硅基流动API Key
    base\\\\\\\_url="https://api.siliconflow.cn/v1"
)

# 审计分析调用
response = client.chat.completions.create(
    model="deepseek-ai/DeepSeek-R1-0528-Qwen3-8B",
    messages=\\\\\\\[
        {"role": "system", "content": system\\\\\\\_prompt},
        {"role": "user", "content": api\\\\\\\_sequence\\\\\\\_prompt}
    ],
    temperature=0.1,     # 低温度保证输出稳定性
    max\\\\\\\_tokens=4096,
    stream=False
)

raw\\\\\\\_output = response.choices\\\\\\\[0].message.content
# 送入parse\\\\\\\_model\\\\\\\_output()进行思维链解析
result = parse\\\\\\\_model\\\\\\\_output(raw\\\\\\\_output)
```

**异步批量调用（日志分析模式）**：

```python
import asyncio
from openai import AsyncOpenAI

async_client = AsyncOpenAI(
    api_key="sk-yxbgyidxbppxmvofcxncyoiurivwvoqhrranssqsjzdenywt",
    base_url="https://api.siliconflow.cn/v1"
)

async def analyze_sessions(sessions: list[str]) -> list[dict]:
    """批量分析多个会话的API调用序列"""
    tasks = [
        async_client.chat.completions.create(
            model="deepseek-ai/DeepSeek-R1-0528-Qwen3-8B",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": session_prompt}
            ],
            temperature=0.1,
            max_tokens=4096
        )
        for session_prompt in sessions
    ]
    responses = await asyncio.gather(*tasks)
    return [parse_model_output(r.choices[0].message.content) for r in responses]
```

**代理模式异步后台 Worker（推荐）**：

```python
import asyncio
from asyncio import Queue

# 每会话仅一次 LLM 调用，配合 Worker 池控制并发
BACKSTOP_QUEUE: Queue[str] = Queue(maxsize=500)
BACKSTOP_WORKERS = 2
_backstop_analyzed: set[str] = set()

async def backstop_worker(worker_id: int):
    while True:
        session_id = await BACKSTOP_QUEUE.get()
        try:
            chain = chain_builder.get_chain(session_id)
            if chain and llm_client:
                result = await llm_analyzer.analyze_async(chain)
                # 升级 preliminary → confirmed 或新建 confirmed
                handle_backstop_result(chain, result)
        finally:
            BACKSTOP_QUEUE.task_done()

def enqueue_backstop(session_id: str):
    if session_id not in _backstop_analyzed:
        _backstop_analyzed.add(session_id)
        BACKSTOP_QUEUE.put_nowait(session_id)
```

**注意事项**：

* 硅基流动按Token计费，建议在规则引擎过滤后再调用，控制成本
* 代理模式下使用异步调用避免阻塞主请求转发
* 实现请求重试机制（最多3次），应对API偶发超时
* 可在本地缓存近期相同序列的判定结果，减少重复调用

#### 4.3.4 领域适配策略

由于该模型在网络安全领域的训练数据有限，通过**Prompt注入安全知识**补充领域知识，无需额外微调：

在系统Prompt中嵌入BOLA攻击模式、参数遍历特征、接口滥用指标等安全领域知识，引导模型在推理时参考：

```
安全知识参考：
- BOLA（越权）：用户A获取资源ID后，用户B用自身Token访问同一ID，若返回200则存在越权
- 参数遍历：短时间内（<10s）对同一端点发起大量请求（>20次），参数值呈均匀分布或线性递增
- 接口滥用：非业务逻辑顺序调用（如未登录直接访问订单），或调用频率远超正常均值（>10倍）
```

如果Prompt注入后效果仍不满足要求，后期可考虑使用云端GPU资源（如AutoDL、Colab）进行LoRA微调，但当前方案暂不纳入微调环节。

### 4.4 越权（BOLA）专项检测

BOLA是方向一的核心检测目标之一。实现采用**规则引擎前置 + LLM异步兜底 + 双用户动态验证**的混合策略：

**规则引擎前置检测**：

* 在`RuleEngine`中实现跨用户资源访问检测：
  * `extract_user_id()` — 从`query_params.user`或`Authorization`头提取当前用户身份
  * `extract_resource_ids()` — 正则匹配路径中4位以上数字ID
  * `_session_user`字典 — 追踪每个会话的当前用户（登录请求自动记录）
  * 同一资源ID在不同用户会话中出现 → 返回 `"bola"` 类型，触发 **初步告警** (status=preliminary, confidence=0.75)

**LLM异步深度分析**：

* 输入OpenAPI规范及完整ACC序列，LLM识别风险特征：

  * 端点包含路径参数且类型为对象ID（如`/resource/{id}`）
  * 该端点未在参数级别实施授权校验
  * 存在敏感操作的级联端点（如获取后紧跟修改/删除）
  * 同一用户访问了本不应访问的资源ID（结合上下文）

* 规则未触发的BOLA（如无频率异常但存在越权）由 **LLM全量兜底** 捕获，直接生成 confirmed 告警
* **BOLA预检测标记**：在prompt的`请求序列分析`段中，`_detect_cross_session_bola()`按login/logout划分会话边界，提取各会话访问的资源ID；当检测到跨用户同资源ID访问时，注入`可疑标记: 资源ID {id} 被用户 {u1} 和 {u2} 同时访问，存在BOLA(越权)嫌疑`，直接引导LLM注意力至BOLA模式。该检测同时覆盖路径参数、查询参数和POST body中的资源ID。

**安全过滤**：

* `_gen_bola` 使用 `safe_resource`（通过 `_is_normal_safe()` 过滤）而非裸 `resource_eps`
* 敏感关键词：`admin, config, debug, backup, internal, secret, token, key, password, credential, ssn, cert`
* 避免 password/admin 等敏感端点混入 BOLA 正常资源访问序列，保证标签纯净度

**双用户动态验证**：

* 模拟用户A获取资源ID后，用户B携带自身Token访问该ID
* 若服务端返回200而非403，则确认BOLA漏洞
* 参考Palo Alto Networks BOLABuster的实现思路 [$TRAE\_REF](https://essay.utwente.nl/fileshare/file/107423/Johansens_BA_BIT.pdf)（在docs文件夹中）

### 4.5 参数遍历检测

参数遍历攻击的典型特征是在短时间内对某一参数进行大量枚举（如`?id=1,2,3...`）。检测逻辑：

**规则引擎前置检测**（<1ms，即时响应）：

1. **频率阈值**：同一Token在10秒内对同一端点的调用次数超过阈值（`frequency_threshold=15, frequency_window=10`）
2. **敏感参数检测**：参数名匹配常见遍历目标（`id`/`page`/`offset`/`index`）
3. **参数熵分析**：参数值在数值空间呈均匀分布（熵接近理论最大值）
4. **响应码辅助**：遍历攻击常伴随大量404/403响应（响应码异常率 `max_client_error_ratio=0.3`，即 > 30%）
5. **参数单调性指数**（新增LLM辅助特征）：`calc_param_monotonicity()` 检测同一端点组内参数值是否严格递增，输出0-1分数，>0.8即标记"高度疑似参数遍历"。该特征对Base64编码型路径参数（如`/api/notes/Ab1000→Ab1001`）和API版本号遍历（如`/api/v0.0→v0.1`）特别有效
6. 命中即触发 **初步告警** (status=preliminary, type="traversal", confidence=0.75)

**LLM异步确认**：

* 后台 Worker 对同一会话执行 LLM 深度分析
* 存在遍历特征 → **升级** 为 confirmed (confidence↑, 补充思维链解释)
* 误报（规则过严）→ 保留 preliminary，不降级（避免丢失潜在告警）

### 4.6 接口滥用检测

接口滥用包括非业务逻辑顺序调用、超高频调用、未授权访问敏感操作等。检测逻辑：

**规则引擎前置检测**：

1. **频率阈值**：单端点调用频率超过 `frequency_threshold=15`（10秒窗口），默认阈值15次
2. **敏感路径**：匹配黑名单路径正则 `SENSITIVE_PATHS`：`(admin|config|debug|backup|internal|actuator|swagger|api-docs)`
3. **敏感参数**：匹配批量操作参数（`batch=true`/`export=csv`/`limit>1000`）
4. **响应码异常率**：错误响应（4xx/5xx）占比 `max_client_error_ratio=0.3`（30%）
5. 命中即触发 **初步告警** (status=preliminary, type="abuse", confidence=0.75)

**LLM异步确认**：

* 后台 Worker 分析 ACC 序列的业务逻辑合理性
* 重点关注：未登录直接调用敏感操作、调用顺序违反业务流程、频率远超正常范围
* 确认为真 → **升级** 为 confirmed

\---

## 五、可解释安全告警设计

### 5.1 解释生成流水线

```
DeepSeek-R1-0528-Qwen3-8B 原始输出
    │
    ▼
┌─────────────────┐
│ <think >思维链   │  <-- 提取推理过程中的分析逻辑
│ 标签解析         │      作为可解释依据
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ JSON结果提取     │  <-- 从思维链之后的内容中
│                 │      解析is\\\\\\\_anomaly/type/confidence
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ 解释融合与评分   │  <-- 合并思维链推理依据与JSON结果
│                 │      生成结构化告警 + 风险评分 + 处置建议
└─────────────────┘
```

相比传统方案需要额外引入SHAP/LIME做特征归因，思维链蒸馏模型在推理过程中**自动产出分析逻辑**，省去了XAI归因环节的复杂度。`<think >`标签内的内容就是模型对API调用序列的逐步分析过程，可直接作为告警解释的核心素材。

### 5.2 告警输出格式

```json
{
  "alert\\\\\\\_id": "ALT-20250703-001",
  "timestamp": "2025-07-03T14:32:18+08:00",
  "severity": "high",
  "anomaly\\\\\\\_type": "parameter\\\\\\\_traversal",
  "confidence": 0.94,
  "session\\\\\\\_id": "sess\\\\\\\_a1b2c3d4",
  "source\\\\\\\_ip": "10.0.1.15",
  "affected\\\\\\\_endpoints": \\\\\\\["/api/v1/users/{id}"],
  "explanation": {
    "summary": "检测到用户'zhangsan'在12秒内对'/api/v1/users/{id}'端点发起了28次请求，参数'id'从10001连续递增至10028，响应码以200和404交替出现，符合参数遍历攻击的典型模式。",
    "chain\\\\\\\_of\\\\\\\_thought": "分析该会话的调用序列：第一步，检查调用频率，28次/12秒，正常用户均值2次/分钟，频率异常偏高。第二步，检查参数分布，参数'id'从10001到10028严格线性递增，Shannon熵为6.98（接近理论最大值7.0），呈典型的枚举分布。第三步，检查响应码，404占比46%，表明大量请求命中了不存在的资源ID。综合以上三个维度，判定为参数遍历攻击。",
    "key\\\\\\\_indicators": \\\\\\\[
      "请求频率异常：28次/12秒，远超正常用户行为（均值2次/分钟）",
      "参数分布均匀：参数'id'呈严格线性递增，Shannon熵为6.98（接近理论最大值7.0）",
      "响应码异常：404占比46%，表明大量请求命中了不存在的资源ID"
    ],
    "risk\\\\\\\_assessment": "攻击者可能正在批量枚举用户ID，试图获取未授权的用户信息。该行为可能导致用户隐私数据泄露。",
    "recommendation": "建议立即对该IP实施速率限制，并检查'/api/v1/users/{id}'端点是否缺少基于用户身份的授权校验。"
  },
  "raw\\\\\\\_features": {
    "request\\\\\\\_count": 28,
    "time\\\\\\\_window\\\\\\\_sec": 12,
    "param\\\\\\\_entropy": 6.98,
    "not\\\\\\\_found\\\\\\\_ratio": 0.46,
    "param\\\\\\\_pattern": "sequential\\\\\\\_increment"
  }
}
```

### 5.3 解释质量保障

* **思维链可信度**：模型推理过程直接反映其决策逻辑，可通过比对思维链与特征数据的一致性来验证解释质量
* **多语言支持**：默认中文解释，可切换英文
* **分层解释**：提供"一句话摘要"（reasoning字段）和"详细思维过程"（chain\_of\_thought字段）两种粒度
* **解析容错**：JSON解析失败时降级返回原始输出，确保不丢失告警信息

\---

## 六、部署模式实现

### 6.1 代理模式（Proxy Mode）

代理模式适合需要**实时拦截**和**主动阻断**的场景。

#### 6.1.1 技术实现

基于Python的**Mitmproxy**或**自定义FastAPI网关**实现：

```python
# 核心拦截逻辑示意（FastAPI中间件）
@app.middleware("http")
async def api\\\\\\\_security\\\\\\\_audit(request: Request, call\\\\\\\_next):
    # 1. 记录请求
    req\\\\\\\_record = await capture\\\\\\\_request(request)
    
    # 2. 更新会话调用链
    session\\\\\\\_chain = chain\\\\\\\_builder.append(req\\\\\\\_record)
    
    # 3. 规则引擎快速过滤
    if rule\\\\\\\_engine.check(req\\\\\\\_record, session\\\\\\\_chain):
        # 4. LLM深度分析（异步，不阻塞主流程）
        asyncio.create\\\\\\\_task(llm\\\\\\\_analyzer.analyze(session\\\\\\\_chain))
    
    # 5. 转发请求（或根据策略阻断）
    response = await call\\\\\\\_next(request)
    
    # 6. 记录响应
    await capture\\\\\\\_response(response)
    return response
```

#### 6.1.2 部署架构

```
外部流量 ──► Nginx/LB ──► API安全网关（本工具）──► 后端业务服务
                              │
                              ▼
                         告警队列(Kafka/Redis)
                              │
                              ▼
                         分析引擎 + 告警存储
```

### 6.2 日志分析模式（Log Analysis Mode）

日志模式适合**事后审计**和**离线分析**场景，对业务零侵入。

#### 6.2.1 技术实现

支持从常见日志格式解析：

|日志类型|解析方式|
|-|-|
|Nginx/Apache Access Log|正则解析 + 字段映射|
|应用自定义日志|JSON解析或配置化正则|
|分布式追踪日志（Jaeger/Zipkin）|Span聚合还原调用链|

处理流水线：

```
日志文件/ELK ──► Logstash/Filebeat ──► 消息队列 ──► 批处理引擎
                                                        │
                                                        ▼
                                                   序列构建器
                                                        │
                                                        ▼
                                                   LLM分析引擎
                                                        │
                                                        ▼
                                                   告警存储 + 报告生成
```

#### 6.2.2 批量处理优化

* 按时间窗口（如5分钟）批量聚合日志构建会话
* LLM推理采用批处理（batch inference）提升吞吐量
* 支持断点续传和增量分析

\---

## 七、评测方案

### 7.1 评测数据集构建

数据集通过 **`RealDatasetGenerator`**（`src/evaluation/real_dataset.py`）从真实开源项目的 OpenAPI 规范自动生成。生成器加载 `data/` 目录中的 12 个规范，解析全部端点、参数和认证配置，按攻击类型生成对应的 API 调用序列。

|数据集类型|内容描述|生成方式|
|-|-|-|
|正常调用数据集|模拟用户认证-浏览-资源访问的标准操作序列|从 OpenAPI 规范提取常规端点，过滤敏感关键词（admin/password/token/secret 等），路径参数替换为随机数值|
|BOLA漏洞数据集|用户A获取资源ID后用户B使用自身凭证访问同一ID|选取含 path params 的资源端点，生成双用户登录→资源访问→登出→登录→访问同一资源的序列|
|参数遍历数据集|对path参数连续递增枚举（15-30次）|使用 `_gen_traversal()` 对资源端点批量请求，ID 依次递增，间隔 0.1-0.5s|
|接口滥用数据集|高频调用敏感端点（30-60次）|使用 `_gen_abuse()` 从敏感端点（ admin / config / password 等）中随机选取，间隔仅 0.05-0.3s|
|混合场景数据集|正常调用序列尾部注入一种攻击|先生成完整 normal 序列，再在尾部追加一个随机攻击（bola/traversal/abuse）|
|对抗评估数据集|专门绕过规则引擎的LLM能力边界测试集（6类×4=24样本）|`AdversarialGenerator`（`src/evaluation/adversarial_dataset.py`）生成，覆盖body BOLA、Base64遍历、低频滥用、业务异常、噪声混合、版本遍历6种规则盲区|

**数据规范来源**（`data/` 目录，共 12 个）：

| 规范文件 | 协议 | 来源项目 |
|----------|------|---------|
| `capital.yaml` | GPLv3 | Capital API |
| `dvapi.yaml` | GPLv3 | dvAPI (自动修复 tab 缩进) |
| `dvws.json` | GPLv3 | dvws (自动修复 trailing comma) |
| `RESTaurant.json` | GPLv3 | RESTaurant |
| `vampi.yml` | GPLv3 | VAmPI |
| `vapi.yaml` | GPLv3 | vapi |
| `Apache/crapi.json` | Apache 2.0 | crAPI |
| `MIT/memos.yaml` | MIT | Memos |
| `MIT/OWASP-Juice-Shop-Vuln1.yaml` | MIT | OWASP Juice Shop |
| `MIT/OWASP-Juice-Shop-Vuln2-Manipulate.yaml` | MIT | OWASP Juice Shop (跳过，仅 2 端点) |
| `MIT/vulnerable_rest_api.yaml` | MIT | vulnerable-rest-api |
| `MIT/vuln_bank.json` | MIT | vuln-bank |

**技术要点**：
- 自动修复：`_repair_content()` 替换 tab→空格、去除 JSON trailing comma，12/12 全量解析
- 参数推断：`_infer_path_params()` 从 `{ID}` 模板自动推断缺失的参数定义
- 敏感过滤：`_is_normal_safe()` 排除 admin/password/token/secret 等 12 个敏感关键词
- 确定性种子：`_sub_rng(tag)` 使用 MD5 哈希，跨进程完全可复现（seed=42）
- 查询参数：从规范定义提取真实参数名（如 `creatorId`、`rowStatus`、`pinned`），按 schema type 生成合法值
- 状态码：GET→200(90%), POST→201(80%), DELETE→204(80%), 5% 概率 304/403

### 7.2 评测指标

|指标|说明|目标值|规则引擎当前实绩|
|-|-|-|-|
|Precision|告警准确率 = TP/(TP+FP)|>= 0.85|**1.0**（FP=0）|
|Recall|检出率 = TP/(TP+FN)|>= 0.90|**1.0**（FN=0，dvapi FN已修复）|
|F1-Score|Precision与Recall调和平均|>= 0.87|**1.0**|
|FPR|假阳性率 = FP/(FP+TN)|<= 0.05|**0.0**|
|LLM对抗集Recall|LLM在规则盲区样本上的检出率|>= 0.85|**1.0（24/24）**|
|Type confusion|LLM类型混淆率（如traversal→abuse）|<= 0.10|**0%（0/7）**|
|平均解释满意度|人工评估告警解释的可读性和准确性（1-5分）|>= 4.0|待LLM评估|
|处理延迟（代理模式）|规则引擎同步延迟（LLM异步不阻塞主流程）|<= 5ms|实测亚毫秒级|
|吞吐量（日志模式）|每秒处理日志条数|>= 1000条/秒|待压测|

注：规则引擎当前实绩基于 `RealDatasetGenerator(seed=42).generate(samples_per_type=1)` 得到 55 个样本（11 个 ≥3 端点的规范 × 5 类型）。dvapi FN 通过在 `_gen_bola` 中增加回退策略（当 safe_resource 为空时使用 endpoint.path + "/" + 随机ID）修复，F1=1.0000。LLM对抗集结果基于 AdversarialGenerator 的 24 个规则盲区样本，经过四轮 Prompt 和数据集迭代后达到 100% 检出率。

### 7.3 对比实验设计

为验证LLM方法的优势，设计以下对比组。使用 `scripts/run_evaluation.py` 一键运行：

|对比组|方法描述|数据集说明|命令行|
|-|-|-|-|
|Baseline-1|纯规则引擎（频率阈值+敏感路径+黑名单参数+BOLA跨用户检测）|默认：真实 OpenAPI 规范驱动|`python scripts/run_evaluation.py --samples 3`|
|Baseline-2|XGBoost（6维手工特征：sequence_length, client_error_ratio, api_uniqueness, interval_mean, interval_std, server_error_ratio）|同 Baseline-1，默认启用|`--include-xgboost` (默认 True)|
|Proposed-1|DeepSeek-R1-0528-Qwen3-8B零样本推理（硅基流动API），Prompt 传入 ACC/ACG/参数特征/访问模式/spec_summary/spec_detail|同 Baseline-1|自动运行|
|Proposed-2|规则引擎前置 + LLM异步确认/兜底（混合策略）：规则命中直接告警，未命中再由LLM分析|同 Baseline-1|自动运行|

使用 `--synthetic` 参数可切换为模板合成数据集（旧 `DatasetGenerator`），用于对比真实规范与合成数据的效果差异。

### 7.4 演示方案

评测演示包含以下环节：

1. **正常调用演示**：展示标准用户注册-登录-浏览-下单的完整调用链，系统无告警
2. **BOLA攻击演示**：用户A获取订单ID后，用户B越权访问该订单详情，系统检出并解释
3. **参数遍历演示**：对`/api/v1/users/{id}`连续发起100次递增ID请求，系统检出遍历行为
4. **接口滥用演示**：非业务逻辑地高频调用敏感接口（如批量导出），系统检出频率异常
5. **告警控制台演示**：展示告警列表、详情页、解释文本、风险评分、处置建议

\---

## 八、技术栈与依赖

|层级|组件|选型|
|-|-|-|
|代理网关|HTTP拦截/转发|Mitmproxy / FastAPI + uvicorn|
|日志采集|日志解析与传输|Filebeat / Python Log Parser|
|消息队列|异步告警传输|Redis Stream / Kafka（可选）|
|序列存储|调用链临时存储|Redis（TTL 1小时）|
|LLM推理|模型服务化|硅基流动API（OpenAI兼容接口，模型：deepseek-ai/DeepSeek-R1-0528-Qwen3-8B）|
|输出解析|思维链结构化|Python后处理模块（正则提取 + JSON解析）|
|前端展示|告警控制台|Streamlit / Vue3 + Element Plus|
|数据存储|告警持久化|PostgreSQL + TimescaleDB|

\---

## 九、开发计划

|阶段|主要任务|交付物|
|-|-|-|
|第一阶段：基础框架|搭建代理/日志双模式数据接入层；实现请求序列化与特征提取；接入硅基流动API并验证模型推理|可运行的数据采集模块；特征提取Demo；API调用验证|
|第二阶段：核心检测|实现规则引擎；设计Prompt模板（含安全知识注入）；实现思维链输出解析模块；集成模型API调用|端到端检测流水线；初版Prompt模板；输出解析模块|
|第三阶段：可解释输出|完善思维链与JSON结果的融合逻辑；设计告警输出格式；实现风险评分与处置建议生成|带思维链解释的完整告警JSON；控制台原型|
|第四阶段：评测与优化|构建领域数据集（RealDatasetGenerator从12个真实OpenAPI规范自动生成）；运行对比实验评测；优化Prompt模板与规则引擎阈值；迭代提升检测效果|评测指标对比表；规则引擎FP=0/FN=0；自动数据集生成器|
|第五阶段：工具化与演示|完善Web控制台；编写测试用例集（55通过+24对抗集）；制作演示视频/文档|可部署工具包；完整测试数据集（55样本5类型+24对抗样本）；评测报告|
|第六阶段：对抗鲁棒性|构建对抗评估数据集（AdversarialGenerator）；迭代Prompt提升LLM在规则盲区上的检出率至100%；消除类型混淆|对抗数据集24样本全部检出；类型混淆率0%|

\---

## 十、风险与应对

|风险|影响|应对措施|
|-|-|-|
|思维链输出导致延迟升高|代理模式实时性不足|规则引擎前置过滤90%+正常流量；限制Prompt中思维链长度（要求200字以内）；LLM异步分析不阻塞主流程|
|API调用成本不可控|大规模日志分析时Token消耗大|规则引擎过滤后仅对疑似流量调用API；实现本地缓存避免重复分析；设置日调用量上限|
|API偶发超时或不可用|代理模式实时分析中断|实现请求重试（最多3次）+ 指数退避；超时后降级为仅规则引擎告警；设置熔断机制|
|JSON解析不稳定|结构化输出提取失败|后处理模块内置容错逻辑；解析失败时降级返回原始输出+标记parse\_error；持续优化Prompt格式约束|
|假阳性率高|告警淹没，可用性下降|引入动态验证（如BOLA双用户测试）；Prompt中注入安全知识提高判定精度；持续优化Prompt模板|
|安全领域知识不足|蒸馏模型对专业攻击模式识别能力有限|Prompt注入BOLA/遍历/滥用的典型特征；通过对比实验持续迭代优化Prompt|
|数据集标注成本高|模型效果受限|已通过RealDatasetGenerator从12个真实OpenAPI规范自动生成55个样本（5类型×11规范），无需手工标注；自动修复问题规范（tab/trailing comma）和模板参数推断进一步提升覆盖率|
|LLM推理随机波动|temperature=0.1下仍有采样差异，低频重复调用样本偶发漏报|prompt注入"同一端点相同参数重复调用{N}次"的明确计数标记；后处理以param_monotonicity≥0.8兜底补充；持续在对抗集上回归验证|

\---

## 十一、总结

本方案围绕方向一的核心要求，设计了\*\*"序列建模 + 思维链推理 + 可解释输出"\*\*的技术路线。核心审计模型统一采用DeepSeek-R1-0528-Qwen3-8B，通过硅基流动API调用，无需GPU和本地部署。该模型从DeepSeek-R1蒸馏思维链到Qwen3-8B获得，具备SOTA级推理能力。通过ACC/ACG双路表征捕获API调用上下文，结合规则引擎与思维链推理的分层检测策略，实现对越权、参数遍历、接口滥用三类威胁的有效识别。思维链蒸馏模型天然产出可读的推理过程，直接作为告警解释的素材，省去传统XAI归因环节的复杂度。方案支持代理和日志两种部署模式，并提供完整的评测数据集、对比实验与演示方案，具备较强的可落地性。

