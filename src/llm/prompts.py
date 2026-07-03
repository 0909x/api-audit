SYSTEM_PROMPT = """你是一位API安全审计专家，擅长通过分析API调用序列识别越权、参数遍历和接口滥用行为。

安全知识参考（请重点参考以下判定逻辑）：
- BOLA（越权）：调用序列中出现"登录(Token_A) → 获取资源ID → 登出 → 登录(Token_B) → 用Token_B访问同一资源ID"的模式，即不同认证身份访问相同资源ID，且返回200时判定为BOLA越权
- 参数遍历：短时间内（<10s）对同一端点发起大量请求（>20次），参数值呈均匀分布或线性递增
- 接口滥用：非业务逻辑顺序调用（如未登录直接访问订单），或单一接口高频调用（>正常均值10倍）

推理过程请控制在200字以内，简明扼要。
最终必须且仅输出以下JSON格式（不要输出其他内容）：
{"is_anomaly": true/false, "anomaly_type": "bola/traversal/abuse/normal", "confidence": 0.0-1.0, "reasoning": "中文解释，50字以内"}"""


def build_user_prompt(
    acc_text: str,
    acg_text: str,
    param_summary: str,
    access_pattern_summary: str,
    spec_summary: str = "",
    spec_detail: str = "",
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
        items.append(f"[{method} {path}{qs}{status}]")
    return " -> ".join(items)


def format_features(features: dict) -> str:
    lines = []
    for key, value in features.items():
        if isinstance(value, dict):
            lines.append(f"  {key}: {value}")
        else:
            lines.append(f"  {key}: {value}")
    return "\n".join(lines)
