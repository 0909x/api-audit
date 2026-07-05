import time
import structlog
from typing import Optional, Any
from openai import OpenAI, AsyncOpenAI

logger = structlog.get_logger()


class CircuitBreaker:
    def __init__(self, threshold: int = 5, cooldown: float = 60.0):
        self.threshold = threshold
        self.cooldown = cooldown
        self._failures = 0
        self._open_until = 0.0

    def record_success(self):
        self._failures = 0

    def record_failure(self):
        self._failures += 1
        if self._failures >= self.threshold:
            self._open_until = time.time() + self.cooldown
            logger.warning("circuit_breaker_opened", until=self._open_until)

    def is_open(self) -> bool:
        if self._open_until == 0:
            return False
        if time.time() >= self._open_until:
            self._open_until = 0
            self._failures = 0
            logger.info("circuit_breaker_closed")
            return False
        return True

    @property
    def state(self) -> str:
        if self._open_until > time.time():
            return "open"
        return "closed" if self._failures < self.threshold else "half-open"


class SiliconFlowClient:
    def __init__(
        self,
        api_key: str,
        base_url: str = "https://api.siliconflow.cn/v1",
        model: str = "deepseek-ai/DeepSeek-R1-0528-Qwen3-8B",
        temperature: float = 0.1,
        max_tokens: int = 8192,
        max_retries: int = 3,
        circuit_breaker_threshold: int = 5,
        circuit_breaker_cooldown: int = 60,
    ):
        self.model = model
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.max_retries = max_retries
        self._client = OpenAI(api_key=api_key, base_url=base_url)
        self._async_client = AsyncOpenAI(api_key=api_key, base_url=base_url)
        self._circuit_breaker = CircuitBreaker(
            threshold=circuit_breaker_threshold,
            cooldown=circuit_breaker_cooldown,
        )

    def analyze(self, system_prompt: str, user_prompt: str) -> dict:
        if self._circuit_breaker.is_open():
            logger.warning("circuit_breaker_open_skipping")
            return {"is_anomaly": False, "anomaly_type": "circuit_breaker_open", "confidence": 0.0, "reasoning": "熔断器已打开，跳过LLM调用"}

        last_error = None
        for attempt in range(1, self.max_retries + 1):
            try:
                response = self._client.chat.completions.create(
                    model=self.model,
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt},
                    ],
                    temperature=self.temperature,
                    max_tokens=self.max_tokens,
                    stream=False,
                )
                raw_output = response.choices[0].message.content or ""
                self._circuit_breaker.record_success()
                return parse_model_output(raw_output)

            except Exception as e:
                last_error = str(e)
                logger.warning("llm_api_retry", attempt=attempt, error=last_error)
                if attempt < self.max_retries:
                    time.sleep(2 ** attempt)
                else:
                    self._circuit_breaker.record_failure()

        return {
            "is_anomaly": False,
            "anomaly_type": "api_error",
            "confidence": 0.0,
            "reasoning": f"LLM调用失败（已重试{self.max_retries}次）: {last_error}",
        }

    async def analyze_async(self, system_prompt: str, user_prompt: str) -> dict:
        if self._circuit_breaker.is_open():
            logger.warning("circuit_breaker_open_skipping")
            return {"is_anomaly": False, "anomaly_type": "circuit_breaker_open", "confidence": 0.0, "reasoning": "熔断器已打开，跳过LLM调用"}

        import asyncio
        last_error = None
        for attempt in range(1, self.max_retries + 1):
            try:
                response = await self._async_client.chat.completions.create(
                    model=self.model,
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt},
                    ],
                    temperature=self.temperature,
                    max_tokens=self.max_tokens,
                )
                raw_output = response.choices[0].message.content or ""
                self._circuit_breaker.record_success()
                return parse_model_output(raw_output)

            except Exception as e:
                last_error = str(e)
                logger.warning("llm_api_async_retry", attempt=attempt, error=last_error)
                if attempt < self.max_retries:
                    await asyncio.sleep(2 ** attempt)
                else:
                    self._circuit_breaker.record_failure()

        return {
            "is_anomaly": False,
            "anomaly_type": "api_error",
            "confidence": 0.0,
            "reasoning": f"LLM调用失败（已重试{self.max_retries}次）: {last_error}",
        }

    async def analyze_batch(self, prompts: list[tuple[str, str]]) -> list[dict]:
        tasks = [self.analyze_async(sp, up) for sp, up in prompts]
        import asyncio
        return await asyncio.gather(*tasks)


def parse_model_output(raw_output: str) -> dict:
    import re
    import json

    think_match = re.search(r"<think>(.*?)</think>", raw_output, re.DOTALL)
    chain_of_thought = think_match.group(1).strip() if think_match else ""

    json_part = re.sub(r"<think>.*?</think>", "", raw_output, flags=re.DOTALL).strip()

    try:
        result = json.loads(json_part)
        if isinstance(result.get("reasoning"), str) and len(result["reasoning"]) < 30 and chain_of_thought:
            result["chain_of_thought"] = chain_of_thought
        return result
    except json.JSONDecodeError:
        pass

    # 尝试修复截断 JSON: 补全尾部、字段名、引号等
    repaired = json_part
    if repaired.count('"') % 2 != 0:
        repaired += '"'
    if not repaired.endswith("}"):
        repaired += "}"
    # 补全截断的字段值
    repaired = re.sub(r'"reasoning"\s*:\s*"[^"]*$', r'"reasoning": "模型输出截断，部分内容丢失"', repaired)
    repaired = re.sub(r'"confidence"\s*:\s*\d+\.?\d*[^,}\s]', lambda m: re.sub(r'([^0-9eE.+\-]).*$', r'\1', m.group(0)), repaired)
    try:
        result = json.loads(repaired)
        if isinstance(result.get("reasoning"), str) and len(result["reasoning"]) < 30 and chain_of_thought:
            result["chain_of_thought"] = chain_of_thought
        if not result.get("reasoning"):
            result["reasoning"] = "模型输出截断，原始输出包含合法JSON"
        return result
    except (json.JSONDecodeError, ValueError):
        return {
            "is_anomaly": False,
            "anomaly_type": "parse_error",
            "confidence": 0.0,
            "reasoning": f"模型输出解析失败，原始输出：{raw_output[:200]}",
            "chain_of_thought": chain_of_thought,
        }
