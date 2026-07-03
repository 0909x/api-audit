import structlog
import asyncio
from typing import Optional, Callable
from src.ingestion.models import RequestRecord

logger = structlog.get_logger()


class BOLAValidator:
    def __init__(self, http_client: Optional[Callable] = None):
        self._http_client = http_client

    async def verify(
        self,
        base_url: str,
        endpoint: str,
        method: str,
        resource_id: str,
        token_a: str,
        token_b: str,
        headers: Optional[dict] = None,
    ) -> dict:
        url = f"{base_url.rstrip('/')}/{endpoint.lstrip('/').replace('{id}', resource_id)}"
        actual_headers = headers or {}

        result_a = await self._do_request(method, url, {**actual_headers, "Authorization": token_a})
        result_b = await self._do_request(method, url, {**actual_headers, "Authorization": token_b})

        status_a = result_a.get("status_code", 0)
        status_b = result_b.get("status_code", 0)

        is_vulnerable = (200 <= status_a < 300) and (200 <= status_b < 300)

        return {
            "is_vulnerable": is_vulnerable,
            "user_a_status": status_a,
            "user_b_status": status_b,
            "user_a_body": result_a.get("body", "")[:200],
            "user_b_body": result_b.get("body", "")[:200],
            "endpoint": url,
            "method": method,
        }

    async def _do_request(self, method: str, url: str, headers: dict) -> dict:
        if self._http_client:
            return await self._http_client(method, url, headers)

        try:
            import httpx
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.request(method, url, headers=headers)
                return {
                    "status_code": resp.status_code,
                    "body": resp.text[:500],
                }
        except ImportError:
            logger.error("httpx_not_available")
            return {"status_code": 0, "body": "httpx not available for HTTP request"}
        except Exception as e:
            logger.error("bola_verify_request_failed", url=url, error=str(e))
            return {"status_code": 0, "body": str(e)}

    @staticmethod
    def extract_resource_id(records: list[RequestRecord]) -> Optional[str]:
        from src.features.param_features import extract_params
        for r in records:
            params = extract_params(r)
            for k, v in params.items():
                if k.startswith("path:") and v.isdigit():
                    return v
        return None

    @staticmethod
    def detect_bola_candidates(chain_records: list[RequestRecord]) -> list[dict]:
        candidates = []
        seen_ids = set()
        for i, r in enumerate(chain_records):
            from src.features.param_features import extract_params
            params = extract_params(r)
            for k, v in params.items():
                if k.startswith("path:") and v.isdigit() and v not in seen_ids:
                    seen_ids.add(v)
                    candidates.append({
                        "resource_id": v,
                        "endpoint": r.path,
                        "method": r.method,
                        "index": i,
                    })
        return candidates
