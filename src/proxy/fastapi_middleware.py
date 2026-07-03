import structlog
from fastapi import FastAPI, Request
from starlette.middleware.base import BaseHTTPMiddleware
from src.ingestion.models import RequestRecord
from src.engine.pipeline import AuditPipeline

logger = structlog.get_logger()


class ApiSecurityMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: FastAPI, pipeline: AuditPipeline):
        super().__init__(app)
        self.pipeline = pipeline

    async def dispatch(self, request: Request, call_next):
        req_record = await self._capture_request(request)
        rule_triggered = await self.pipeline.process_request_async(req_record)
        response = await call_next(request)
        req_record.status_code = response.status_code
        if rule_triggered:
            logger.warning("request_blocked_by_rule", path=request.url.path, session=req_record.session_id)
        return response

    async def _capture_request(self, request: Request) -> RequestRecord:
        body = None
        try:
            body_bytes = await request.body()
            body = body_bytes.decode("utf-8", errors="replace")[:4096] if body_bytes else None
        except Exception:
            pass

        auth_header = request.headers.get("authorization", "")
        session_cookie = request.cookies.get("session", "")
        session_id = auth_header or session_cookie or (request.client.host if request.client else "unknown")

        return RequestRecord(
            method=request.method,
            path=request.url.path,
            query_params=dict(request.query_params),
            headers=dict(request.headers),
            body=body,
            session_id=session_id,
            source_ip=request.client.host if request.client else None,
        )


def setup_proxy(pipeline: AuditPipeline) -> FastAPI:
    app = FastAPI(title="API Security Audit Gateway")
    app.add_middleware(ApiSecurityMiddleware, pipeline=pipeline)

    @app.get("/health")
    async def health():
        return {"status": "ok", "stats": pipeline.get_stats()}

    @app.get("/alerts")
    async def get_alerts(limit: int = 100, offset: int = 0):
        alerts = pipeline.alert_store.get_all(limit=limit, offset=offset)
        return [a.model_dump() for a in alerts]

    @app.get("/alerts/{alert_id}")
    async def get_alert(alert_id: str):
        alert = pipeline.alert_store.get_by_id(alert_id)
        return alert.model_dump() if alert else {"error": "not_found"}

    @app.get("/stats")
    async def get_stats():
        return pipeline.get_stats()

    return app
