from pydantic_settings import BaseSettings
from typing import ClassVar


class Settings(BaseSettings):
    model_config = {"env_file": ".env", "env_file_encoding": "utf-8"}

    # LLM
    siliconflow_api_key: str = "sk-yxbgyidxbppxmvofcxncyoiurivwvoqhrranssqsjzdenywt"
    siliconflow_api_url: str = "https://api.siliconflow.cn/v1"
    llm_model: str = "deepseek-ai/DeepSeek-R1-0528-Qwen3-8B"
    llm_temperature: float = 0.1
    llm_max_tokens: int = 8192
    llm_max_retries: int = 3
    llm_circuit_breaker_threshold: int = 5
    llm_circuit_breaker_cooldown: int = 60

    # Proxy
    proxy_host: str = "0.0.0.0"
    proxy_port: int = 8080

    # Session
    session_window_seconds: int = 1800
    max_chain_length: int = 128
    session_cleanup_interval: int = 300

    # Logging
    log_level: str = "INFO"

    # LLM backstop (rule-first, LLM-as-fallback)
    llm_backstop_enabled: bool = True
    llm_backstop_workers: int = 2
    llm_backstop_queue_size: int = 500

    # Feature thresholds
    traversal_time_window: int = 10
    traversal_request_threshold: int = 20
    abuse_frequency_multiplier: float = 10.0

    ALERT_SOURCE: ClassVar[str] = "api-security-audit"


settings = Settings()
