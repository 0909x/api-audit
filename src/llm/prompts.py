SYSTEM_PROMPT = """你是一位API安全审计专家，擅长通过分析API调用序列识别越权、参数遍历和接口滥用行为。

安全知识参考（请重点参考以下判定逻辑）：
- BOLA（越权）：调用序列中出现"登录(Token_A) → 获取资源ID → 登出 → 登录(Token_B) → 用Token_B访问同一资源ID"的模式，即不同认证身份访问相同资源ID，且返回200时判定为BOLA越权。注意：BOLA不需要大量请求，只要出现"不同Token访问同一资源"即可判定。跨会话BOLA：用户A访问某资源ID后登出，用户B登入后访问同一资源ID也构成BOLA。
- 参数遍历：对同一端点发起请求，参数值呈线性递增或均匀分布（即使请求次数少于20次）。典型特征：路径参数单调递增（如 /api/notes/Ab1000 → Ab1001 → Ab1002），步长固定。注意请求次数少但参数值严格递增也算遍历。
- 接口滥用：非业务逻辑顺序调用（如未登录直接访问订单），或单一接口高频调用（>正常均值10倍），或同一参数被重复调用。特别注意：普通用户访问标注了[管理员权限]或[需特定角色]的端点（如reports/summary、admin、force删除等），即使单次调用也构成权限越界型滥用。

特别注意：
- 请求序列中即使大部分请求看似正常，只要其中存在上述任何一种模式，就应判定为异常
- "请求序列分析"部分的"端点频率分布"、"参数单调递增指数"和"可疑标记"对判定非常重要：如果某个端点占比极高且参数单调递增，高度疑似遍历
- OpenAPI规范信息中描述了标准业务流程：如果调用顺序违反(如跳过必要步骤)，也构成异常
- 单个请求也可能异常（如违反业务逻辑的操作）

推理过程请控制在200字以内，简明扼要。
最终必须且仅输出以下JSON格式（不要输出其他内容）：
{"is_anomaly": true/false, "anomaly_type": "bola/traversal/abuse/normal", "confidence": 0.0-1.0, "reasoning": "中文解释，200字以内"}"""


def build_user_prompt(
    acc_text: str,
    acg_text: str,
    param_summary: str,
    access_pattern_summary: str,
    spec_summary: str = "",
    spec_detail: str = "",
    sequence_summary: str = "",
) -> str:
    parts = []

    parts.append("调用序列（ACC）：")
    parts.append(acc_text)
    parts.append("")

    parts.append("调用关系图（ACG）：")
    parts.append(acg_text)
    parts.append("")

    parts.append("参数特征摘要：")
    parts.append(param_summary)
    parts.append("")

    parts.append("访问模式统计：")
    parts.append(access_pattern_summary)
    parts.append("")

    if sequence_summary:
        parts.append("请求序列分析：")
        parts.append(sequence_summary)
        parts.append("")

    if spec_summary:
        parts.append("OpenAPI规范信息：")
        parts.append(spec_summary)
        parts.append("")

    if spec_detail:
        parts.append("OpenAPI端点详情：")
        parts.append(spec_detail)
        parts.append("")

    return "\n".join(parts)


def format_acc(records: list) -> str:
    items = []
    for r in records:
        method = r.method if hasattr(r, "method") else r.get("method", "GET")
        path = r.path if hasattr(r, "path") else r.get("path", "/")
        status = ""
        status_code = r.status_code if hasattr(r, "status_code") else r.get("status_code")
        if status_code:
            status = f" [{status_code}]"
        qp = r.query_params if hasattr(r, "query_params") else r.get("query_params", {})
        qs = ""
        if qp:
            pairs = [f"{k}={v}" for k, v in qp.items()]
            qs = " ?" + "&".join(pairs)
        body_str = ""
        body = r.body if hasattr(r, "body") else r.get("body")
        if body:
            body_str = f" body:{body[:120]}"
        items.append(f"[{method} {path}{qs}{body_str}{status}]")
    return " -> ".join(items)


def format_features(features: dict) -> str:
    lines = []
    for key, value in features.items():
        if isinstance(value, dict):
            lines.append(f"  {key}: {value}")
        else:
            lines.append(f"  {key}: {value}")
    return "\n".join(lines)
