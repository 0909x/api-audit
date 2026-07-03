import json
import structlog
from datetime import datetime
from mitmproxy import http
from src.ingestion.models import RequestRecord

logger = structlog.get_logger()


class ApiSecurityAddon:
    def __init__(self, chain_builder=None, rule_engine=None, llm_analyzer=None):
        self.chain_builder = chain_builder
        self.rule_engine = rule_engine
        self.llm_analyzer = llm_analyzer

    def request(self, flow: http.HTTPFlow):
        req = flow.request
        body = req.text if req.text else None

        auth_header = req.headers.get("authorization", "")
        session_cookie = req.cookies.get("session", "")
        client_ip = flow.client_conn.peername[0] if flow.client_conn else None
        session_id = auth_header or session_cookie or client_ip or "unknown"

        record = RequestRecord(
            timestamp=datetime.now(),
            method=req.method,
            path=req.path,
            query_params=dict(req.query),
            headers=dict(req.headers),
            body=body,
            session_id=session_id,
            source_ip=client_ip,
        )

        if self.chain_builder:
            self.chain_builder.append(record)

    def response(self, flow: http.HTTPFlow):
        resp = flow.response
        if self.chain_builder and flow.request:
            auth_header = flow.request.headers.get("authorization", "")
            session_cookie = flow.request.cookies.get("session", "")
            client_ip = flow.client_conn.peername[0] if flow.client_conn else None
            session_id = auth_header or session_cookie or client_ip or "unknown"
            chain = self.chain_builder.get_chain(session_id)
            if chain and chain.records:
                chain.records[-1].status_code = resp.status_code
                chain.records[-1].response_body = resp.text[:2048] if resp.text else None

        if self.rule_engine and self.chain_builder and flow.request:
            auth_header = flow.request.headers.get("authorization", "")
            session_cookie = flow.request.cookies.get("session", "")
            client_ip = flow.client_conn.peername[0] if flow.client_conn else None
            session_id = auth_header or session_cookie or client_ip or "unknown"
            chain = self.chain_builder.get_chain(session_id)
            if chain and self.rule_engine.check(chain.records[-1], chain):
                if self.llm_analyzer:
                    import asyncio
                    asyncio.create_task(self.llm_analyzer.analyze(chain))


addons = [ApiSecurityAddon()]
