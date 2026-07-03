import structlog
import asyncio
import threading
from typing import Optional
from src.sequence.chain_builder import ChainBuilder, ApiCallChain
from src.engine.rule_engine import RuleEngine
from src.engine.llm_analyzer import LLMAnalyzer
from src.engine.explanation import generate_alert
from src.engine.alert_store import AlertStore
from src.ingestion.models import RequestRecord
from config.settings import settings

logger = structlog.get_logger()


class AuditPipeline:
    def __init__(
        self,
        chain_builder: Optional[ChainBuilder] = None,
        rule_engine: Optional[RuleEngine] = None,
        llm_analyzer: Optional[LLMAnalyzer] = None,
        alert_store: Optional[AlertStore] = None,
    ):
        self.chain_builder = chain_builder or ChainBuilder()
        self.rule_engine = rule_engine or RuleEngine()
        self.llm_analyzer = llm_analyzer or LLMAnalyzer(None)
        self.alert_store = alert_store or AlertStore()
        self._alert_counter = 0
        self._lock = threading.Lock()
        self._backstop_analyzed: set[str] = set()
        self._backstop_lock = threading.Lock()
        self._backstop_queue: asyncio.Queue[str] = asyncio.Queue(
            maxsize=settings.llm_backstop_queue_size
        )
        self._backstop_workers: list[asyncio.Task] = []
        self._backstop_started = False

    def _start_backstop(self):
        if self._backstop_started:
            return
        self._backstop_started = True
        for i in range(settings.llm_backstop_workers):
            worker = asyncio.create_task(
                self._backstop_worker(i), name=f"backstop-{i}"
            )
            self._backstop_workers.append(worker)
            logger.info("backstop_worker_started", worker=i)

    async def _backstop_worker(self, worker_id: int):
        while True:
            session_id = await self._backstop_queue.get()
            try:
                chain = self.chain_builder.get_chain(session_id)
                if not chain or not chain.records:
                    continue
                if not self.llm_analyzer.client:
                    continue
                result = await self.llm_analyzer.analyze_async(chain)
                self._handle_backstop_result(chain, result)
            except Exception as e:
                logger.error("backstop_error", worker=worker_id, session=session_id, error=str(e))
            finally:
                self._backstop_queue.task_done()

    def _handle_backstop_result(self, chain: ApiCallChain, llm_result: dict):
        at = llm_result.get("anomaly_type", "normal")
        if at in ("parse_error", "api_error", "circuit_breaker_open"):
            return
        session_id = chain.session_id

        with self._lock:
            preliminary = self.alert_store.get_preliminary_by_session_id(session_id)

        if at == "normal":
            if preliminary:
                logger.info("backstop_kept_preliminary", session=session_id, type=preliminary.anomaly_type)
            return

        if preliminary:
            if preliminary.anomaly_type == at:
                self.alert_store.upgrade_alert(preliminary.alert_id, llm_result)
                logger.info("backstop_upgraded", alert_id=preliminary.alert_id, session=session_id, type=at)
                return
            else:
                logger.info("backstop_new_type_found", session=session_id, rule_type=preliminary.anomaly_type, llm_type=at)

        if self.alert_store.has_confirmed_alert(session_id, at):
            logger.info("backstop_dedup_skipped", session=session_id, type=at)
            return

        with self._lock:
            self._alert_counter += 1
            counter = self._alert_counter
        alert = generate_alert(chain, llm_result, alert_index=counter, status="confirmed")
        self.alert_store.add(alert)
        logger.info(
            "backstop_alert_generated",
            alert_id=alert.alert_id,
            severity=alert.severity,
            anomaly_type=alert.anomaly_type,
            confidence=alert.confidence,
            session=alert.session_id,
        )

    def process_request(self, record: RequestRecord) -> bool:
        self.chain_builder.append(record)
        session_chain = self.chain_builder.get_chain(record.session_id or "")
        if not session_chain:
            return False

        alert_type = self.rule_engine.check(record, session_chain)
        if alert_type:
            session_id = record.session_id or ""
            if self.alert_store.has_confirmed_alert(session_id, alert_type):
                return True
            if self.alert_store.get_preliminary_by_session_id(session_id):
                return True
            with self._lock:
                self._alert_counter += 1
                counter = self._alert_counter
            alert = generate_alert(
                session_chain,
                {
                    "is_anomaly": True,
                    "anomaly_type": alert_type,
                    "confidence": 0.75,
                    "reasoning": f"规则引擎触发，检测到{alert_type}异常访问模式",
                },
                alert_index=counter,
                status="preliminary",
            )
            self.alert_store.add(alert)
            logger.info(
                "preliminary_alert_generated",
                alert_id=alert.alert_id,
                anomaly_type=alert.anomaly_type,
                session=alert.session_id,
            )
            return True
        return False

    def _classify_rule_match(self, record: RequestRecord, chain: ApiCallChain) -> str:
        return self.rule_engine.check(record, chain) or "abuse"

    async def process_request_async(self, record: RequestRecord) -> bool:
        rule_triggered = self.process_request(record)
        if not settings.llm_backstop_enabled or not self.llm_analyzer.client:
            return rule_triggered

        session_id = record.session_id or ""
        with self._backstop_lock:
            if session_id in self._backstop_analyzed:
                return rule_triggered
            self._backstop_analyzed.add(session_id)

        self._start_backstop()
        try:
            self._backstop_queue.put_nowait(session_id)
        except asyncio.QueueFull:
            logger.warning("backstop_queue_full", session=session_id)
        return rule_triggered

    def _handle_result(self, chain: ApiCallChain, llm_result: dict):
        with self._lock:
            self._alert_counter += 1
            counter = self._alert_counter
        alert = generate_alert(chain, llm_result, alert_index=counter)
        self.alert_store.add(alert)
        if alert.anomaly_type != "normal":
            logger.info(
                "alert_generated",
                alert_id=alert.alert_id,
                severity=alert.severity,
                anomaly_type=alert.anomaly_type,
                confidence=alert.confidence,
                session=alert.session_id,
            )

    def get_stats(self) -> dict:
        stats = self.alert_store.count()
        return {
            "chain_count": self.chain_builder.active_session_count,
            "backstop_analyzed": len(self._backstop_analyzed),
            "backstop_queue_size": self._backstop_queue.qsize() if hasattr(self, '_backstop_queue') else 0,
            "preliminary": stats.get("preliminary", 0),
            "confirmed": stats.get("confirmed", 0),
            **stats,
        }
