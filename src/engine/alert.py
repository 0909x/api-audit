from datetime import datetime
from pydantic import BaseModel, Field
from typing import Optional


class AlertExplanation(BaseModel):
    summary: str = ""
    chain_of_thought: str = ""
    key_indicators: list[str] = Field(default_factory=list)
    risk_assessment: str = ""
    recommendation: str = ""


class RawFeatures(BaseModel):
    request_count: int = 0
    time_window_sec: float = 0.0
    param_entropy: float = 0.0
    not_found_ratio: float = 0.0
    param_pattern: str = ""


class Alert(BaseModel):
    alert_id: str = ""
    timestamp: str = ""
    status: str = "confirmed"  # preliminary | confirmed | dismissed
    severity: str = "medium"
    anomaly_type: str = "normal"
    confidence: float = 0.0
    session_id: str = ""
    source_ip: str = "0.0.0.0"
    affected_endpoints: list[str] = Field(default_factory=list)
    explanation: AlertExplanation = Field(default_factory=AlertExplanation)
    raw_features: RawFeatures = Field(default_factory=RawFeatures)
    raw_llm_output: str = ""

    @property
    def is_preliminary(self) -> bool:
        return self.status == "preliminary"

    @property
    def is_confirmed(self) -> bool:
        return self.status == "confirmed"


SEVERITY_MAP = {
    "bola": "critical",
    "traversal": "high",
    "abuse": "medium",
    "normal": "info",
}

ALERT_TYPE_LABELS = {
    "bola": "越权访问 (BOLA)",
    "traversal": "参数遍历攻击",
    "abuse": "接口滥用",
    "normal": "正常",
}

RECOMMENDATIONS = {
    "bola": "建议立即检查该端点是否在参数级别实施了基于用户身份的授权校验。可参考OWASP API Security Top 10 #1 (BOLA) 进行修复。",
    "traversal": "建议对该端点实施速率限制，并对参数值进行随机化或基于Session的Token化，避免使用连续递增的整数ID。",
    "abuse": "建议对异常高频的IP或用户实施临时封禁，并检查相关接口是否存在批量操作未做限流控制的缺陷。",
}
