from datetime import datetime
from pydantic import BaseModel, Field
from typing import Optional


class AlertExplanation(BaseModel):
    summary: str = ""
    chain_of_thought: str = ""
    key_indicators: list[str] = Field(default_factory=list)
    risk_assessment: str = ""


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
