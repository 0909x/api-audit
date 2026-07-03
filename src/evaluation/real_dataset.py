"""OpenAPI specification-driven dataset generator.

Loads real vulnerable OpenAPI specs from data/ and generates
realistic normal/anomaly API sequences for evaluation.
"""
import os
import re
import random
import structlog
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from typing import Optional
from src.ingestion.openapi_parser import load_spec, extract_security_info, format_spec_summary, format_spec_detail

logger = structlog.get_logger()
DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "data")


@dataclass
class RealSample:
    session_id: str
    records: list[dict]
    label: str
    sub_type: str = ""
    spec_name: str = ""
    spec_summary: str = ""
    spec_detail: str = ""


class RealDatasetGenerator:
    """Generates evaluation datasets from real OpenAPI specifications."""

    def __init__(self, seed: int = 42, data_dir: str = DATA_DIR):
        self.seed = seed
        self.rng = random.Random(seed)
        self.data_dir = data_dir
        self.specs = self._discover_specs()

    def _sub_rng(self, tag: str) -> random.Random:
        """Create a deterministic sub-RNG using a fixed hash (not Python's hash())."""
        import hashlib
        h = hashlib.md5(tag.encode()).hexdigest()
        return random.Random(int(h[:8], 16) + self.seed)

    def _discover_specs(self) -> list[dict]:
        """Discover and load all OpenAPI specs from data directory."""
        specs = []
        extensions = (".yaml", ".yml", ".json")
        for root, dirs, files in os.walk(self.data_dir):
            for f in files:
                if f.endswith(extensions) and f not in ("LICENSE", "README.md"):
                    path = os.path.join(root, f)
                    spec = load_spec(path)
                    if spec:
                        rel = os.path.relpath(path, self.data_dir)
                        specs.append({
                            "path": rel,
                            "spec": spec,
                            "security": extract_security_info(spec),
                            "summary": format_spec_summary(spec),
                            "detail": format_spec_detail(spec),
                        })
                        logger.info("spec_loaded", path=rel)
        logger.info("spec_discovery_done", total=len(specs))
        return specs

    @staticmethod
    def _infer_path_params(path: str) -> list[dict]:
        """Infer path parameters from URL template when spec lacks parameter definitions."""
        template_pattern = re.compile(r"\{(\w+)\}")
        names = template_pattern.findall(path)
        return [{"name": n, "in": "path", "schema": {"type": "string"}} for n in names]

    def _spec_endpoints(self, spec_info: dict) -> list[dict]:
        """Return a list of endpoint dicts for a spec, merging path-level params."""
        endpoints = []
        spec = spec_info["spec"]
        paths = spec.get("paths", {})
        for path, methods in paths.items():
            if not isinstance(methods, dict):
                continue
            path_level_params = methods.get("parameters", [])
            for method, details in methods.items():
                if method in ("parameters",) or not isinstance(details, dict):
                    continue
                method_params = details.get("parameters", [])
                all_params = path_level_params + method_params
                path_params = [p for p in all_params if p.get("in") == "path"]
                if not path_params:
                    path_params = self._infer_path_params(path)
                query_params = [p for p in all_params if p.get("in") == "query"]
                summary = details.get("summary", "")
                tags = details.get("tags", [])
                endpoints.append({
                    "method": method.upper(),
                    "path": path,
                    "path_params": path_params,
                    "query_params_def": query_params,
                    "summary": summary,
                    "tags": tags,
                    "security": details.get("security", spec.get("security", [])),
                    "has_auth": bool(details.get("security", spec.get("security", []))),
                })
        return endpoints

    def _find_auth_endpoints(self, endpoints: list[dict]) -> list[dict]:
        keywords = {"login", "signin", "signup", "register", "token", "auth"}
        return [e for e in endpoints
                if any(k in e["path"].lower() or k in e["summary"].lower() for k in keywords)]

    def _find_profile_endpoints(self, endpoints: list[dict]) -> list[dict]:
        segments = {"/profile", "/me", "/dashboard", "user/me"}
        return [e for e in endpoints
                if any(seg in e["path"].lower() for seg in segments)]

    def _find_resource_endpoints(self, endpoints: list[dict]) -> list[dict]:
        """Find endpoints with path params (potential BOLA/traversal targets)."""
        return [e for e in endpoints if e["path_params"]]

    SENSITIVE_KEYWORDS = [
        "admin", "config", "debug", "backup", "internal", "secret",
        "token", "key", "password", "credential", "ssn", "cert",
    ]

    def _find_sensitive_endpoints(self, endpoints: list[dict]) -> list[dict]:
        sensitive = {"admin", "export", "delete", "config", "batch", "debug",
                     "secret", "flag", "sup3r", "create_admin", "approve_loan",
                     "key", "password", "token", "credential"}
        return [e for e in endpoints
                if any(k in e["path"].lower() for k in sensitive)]

    def _is_normal_safe(self, path: str) -> bool:
        """Check path won't trigger blacklisted param rule."""
        path_lower = path.lower()
        for kw in self.SENSITIVE_KEYWORDS:
            if kw in path_lower:
                return False
        return True

    def _pick_status(self, method: str, rng: random.Random) -> int:
        method = method.upper()
        if method == "POST":
            return rng.choices([201, 200, 403], weights=[80, 10, 10])[0]
        elif method == "DELETE":
            return rng.choices([204, 200, 403], weights=[80, 10, 10])[0]
        elif method == "PATCH":
            return rng.choices([200, 204, 403], weights=[90, 5, 5])[0]
        else:
            return rng.choices([200, 304, 403], weights=[90, 5, 5])[0]

    def _make_record(self, method: str, path: str, status: int = 200,
                     query_params: Optional[dict] = None, delta_sec: float = 0) -> dict:
        return {
            "method": method,
            "path": path,
            "status_code": status,
            "query_params": query_params or {},
            "timestamp_delta": delta_sec,
        }

    def _resolve_path(self, path: str, path_params: list[dict],
                      rng: random.Random) -> str:
        """Replace path template params with concrete values."""
        result = path
        for p in path_params:
            name = p.get("name", "id")
            ptype = (p.get("schema") or {}).get("type", "string") if isinstance(p, dict) else "string"
            if ptype == "integer":
                val = str(rng.randint(1000, 99999))
            elif ptype == "number":
                val = str(rng.randint(1000, 99999))
            else:
                val = str(rng.randint(10000, 99999))
            result = result.replace(f"{{{name}}}", val)
        return result

    def generate(self, samples_per_type: int = 20, spec_filter: Optional[str] = None) -> list[RealSample]:
        all_samples = []
        if not self.specs:
            logger.warning("no_specs_found_falling_back")
            return []

        for spec_info in self.specs:
            if spec_filter and spec_filter not in spec_info["path"]:
                continue

            endpoints = self._spec_endpoints(spec_info)
            if len(endpoints) < 3:
                continue

            auth_eps = self._find_auth_endpoints(endpoints)
            profile_eps = self._find_profile_endpoints(endpoints)
            resource_eps = self._find_resource_endpoints(endpoints)
            sensitive_eps = self._find_sensitive_endpoints(endpoints)

            browse_eps = [e for e in endpoints
                          if e not in auth_eps
                          and e not in sensitive_eps
                          and (e["has_auth"] or "GET" in e["method"])]

            for i in range(samples_per_type):
                sid = f"{self._spec_tag(spec_info)}_{i:04d}"

                for label in ("normal", "bola", "traversal", "abuse", "mixed"):
                    if label == "normal":
                        sample = self._gen_normal(sid, spec_info, endpoints,
                                                  auth_eps, profile_eps, browse_eps, resource_eps, i)
                    elif label == "bola":
                        sample = self._gen_bola(sid, spec_info, endpoints,
                                                auth_eps, resource_eps, i)
                    elif label == "traversal":
                        sample = self._gen_traversal(sid, spec_info, resource_eps, i)
                    elif label == "abuse":
                        sample = self._gen_abuse(sid, spec_info, sensitive_eps, auth_eps, i)
                    else:
                        sample = self._gen_mixed(sid, spec_info, endpoints, auth_eps,
                                                 profile_eps, browse_eps, resource_eps,
                                                 sensitive_eps, i)

                    sample.spec_name = spec_info["path"]
                    sample.spec_summary = spec_info["summary"]
                    sample.spec_detail = spec_info["detail"]
                    all_samples.append(sample)

        self.rng.shuffle(all_samples)
        logger.info("real_dataset_generated", total=len(all_samples),
                    spec_count=len(self.specs))
        return all_samples

    def _spec_tag(self, spec_info: dict) -> str:
        name = os.path.splitext(os.path.basename(spec_info["path"]))[0]
        return re.sub(r'[^a-zA-Z0-9_]', '_', name)[:20]

    def _gen_normal(self, sid: str, spec_info: dict, endpoints: list[dict],
                    auth_eps: list[dict], profile_eps: list[dict],
                    browse_eps: list[dict], resource_eps: list[dict],
                    idx: int) -> RealSample:
        records = []
        t = 0
        rng = self._sub_rng(f"{sid}_normal")

        safe_browse = [e for e in browse_eps
                       if self._is_normal_safe(e["path"])]
        safe_resource = [e for e in resource_eps
                         if self._is_normal_safe(e["path"])]
        safe_auth = [e for e in auth_eps
                     if self._is_normal_safe(e["path"])]
        safe_profile = [e for e in profile_eps if self._is_normal_safe(e["path"])]

        if safe_auth:
            ep = rng.choice(safe_auth)
            records.append(self._make_record(ep["method"], ep["path"],
                           self._pick_status(ep["method"], rng), delta_sec=t))
            t += rng.uniform(0.5, 2.0)

        browse_count = rng.randint(2, 5) if safe_browse else 0
        for _ in range(browse_count):
            ep = rng.choice(safe_browse)
            params = {}
            qp_defs = ep.get("query_params_def", [])
            for qp in qp_defs:
                if rng.random() < 0.6:
                    ptype = (qp.get("schema") or {}).get("type", "string")
                    if ptype == "integer":
                        params[qp["name"]] = str(rng.randint(1, 100))
                    elif ptype == "number":
                        params[qp["name"]] = f"{rng.randint(1, 100):.2f}"
                    elif qp.get("schema", {}).get("enum"):
                        params[qp["name"]] = rng.choice(qp["schema"]["enum"])
                    else:
                        params[qp["name"]] = f"val_{rng.randint(1, 999)}"
            path = self._resolve_path(ep["path"], ep["path_params"], rng)
            records.append(self._make_record(ep["method"], path,
                           self._pick_status(ep["method"], rng),
                           query_params=params, delta_sec=t))
            t += rng.uniform(0.5, 3.0)

        if safe_profile:
            ep = rng.choice(safe_profile)
            path = self._resolve_path(ep["path"], ep["path_params"], rng)
            records.append(self._make_record(ep["method"], path,
                           self._pick_status(ep["method"], rng), delta_sec=t))
            t += rng.uniform(0.5, 2.0)

        if safe_resource:
            ep = rng.choice(safe_resource)
            path = self._resolve_path(ep["path"], ep["path_params"], rng)
            records.append(self._make_record(ep["method"], path,
                           self._pick_status(ep["method"], rng), delta_sec=t))

        return RealSample(session_id=f"{sid}_normal", records=records,
                          label="normal", sub_type="normal")

    def _gen_bola(self, sid: str, spec_info: dict, endpoints: list[dict],
                  auth_eps: list[dict], resource_eps: list[dict],
                  idx: int) -> RealSample:
        records = []
        t = 0
        rng = self._sub_rng(f"{sid}_bola")

        safe_auth = [e for e in auth_eps if self._is_normal_safe(e["path"])]
        safe_resource = [e for e in resource_eps if self._is_normal_safe(e["path"])]

        login_a = rng.choice(safe_auth) if safe_auth else (rng.choice(auth_eps) if auth_eps else endpoints[0])
        records.append(self._make_record(login_a["method"], login_a["path"], 200,
                       query_params={"user": "userA"}, delta_sec=t))
        t += 1.0

        resource_path = ""
        resource_method = "GET"
        if safe_resource:
            ep = rng.choice(safe_resource)
            resource_method = ep["method"]
            resource_path = self._resolve_path(ep["path"], ep["path_params"], rng)
            records.append(self._make_record(resource_method, resource_path, 200, delta_sec=t))
            t += 0.5

        records.append(self._make_record("POST", "/api/v1/logout", 200, delta_sec=t))
        t += 1.0

        login_b = rng.choice(safe_auth) if safe_auth else (rng.choice(auth_eps) if auth_eps else endpoints[0])
        records.append(self._make_record(login_b["method"], login_b["path"], 200,
                       query_params={"user": "userB"}, delta_sec=t))
        t += 0.5

        if resource_path:
            records.append(self._make_record(resource_method, resource_path, 200, delta_sec=t))

        return RealSample(session_id=f"{sid}_bola", records=records,
                          label="bola", sub_type="bola")

    def _gen_traversal(self, sid: str, spec_info: dict,
                       resource_eps: list[dict], idx: int) -> RealSample:
        records = []
        t = 0
        rng = self._sub_rng(f"{sid}_traversal")

        base_id = 10000
        count = rng.randint(15, 30)
        ep = rng.choice(resource_eps) if resource_eps else {
            "method": "GET", "path": "/api/v1/users/{id}",
            "path_params": [{"name": "id", "schema": {"type": "integer"}}],
        }

        for j in range(count):
            uid = base_id + idx * 100 + j
            status = 200 if j % 3 != 0 else 404
            path = ep["path"]
            for p in ep["path_params"]:
                path = path.replace(f"{{{p['name']}}}", str(uid))
            records.append(self._make_record(ep["method"], path, status, delta_sec=t))
            t += rng.uniform(0.1, 0.5)

        return RealSample(session_id=f"{sid}_traversal", records=records,
                          label="traversal", sub_type="traversal")

    def _gen_abuse(self, sid: str, spec_info: dict,
                   sensitive_eps: list[dict], auth_eps: list[dict],
                   idx: int) -> RealSample:
        records = []
        t = 0
        rng = self._sub_rng(f"{sid}_abuse")

        count = rng.randint(30, 60)
        abuse_eps = sensitive_eps if sensitive_eps else [{
            "method": "GET", "path": "/api/v1/export/all",
            "path_params": [],
        }]

        for j in range(count):
            ep = rng.choice(abuse_eps)
            records.append(self._make_record(
                ep["method"], ep["path"], 200,
                query_params={"format": "json"},
                delta_sec=t,
            ))
            t += rng.uniform(0.05, 0.3)

        return RealSample(session_id=f"{sid}_abuse", records=records,
                          label="abuse", sub_type="abuse")

    def _gen_mixed(self, sid: str, spec_info: dict, endpoints: list[dict],
                   auth_eps: list[dict], profile_eps: list[dict],
                   browse_eps: list[dict], resource_eps: list[dict],
                   sensitive_eps: list[dict], idx: int) -> RealSample:
        rng = self._sub_rng(f"{sid}_mixed")
        base = self._gen_normal(sid, spec_info, endpoints, auth_eps,
                                profile_eps, browse_eps, resource_eps, idx)

        attack_type = rng.choice(["bola", "traversal", "abuse"])
        inject = None
        safe_resource = [e for e in resource_eps
                         if self._is_normal_safe(e["path"])]
        if attack_type == "bola" and safe_resource:
            inject = self._gen_bola(sid, spec_info, endpoints, auth_eps, safe_resource, idx)
        elif attack_type == "traversal" and safe_resource:
            inject = self._gen_traversal(sid, spec_info, safe_resource, idx)
        else:
            inject = self._gen_abuse(sid, spec_info, sensitive_eps, auth_eps, idx)

        if inject:
            max_time = max(r["timestamp_delta"] for r in base.records)
            for rec in inject.records:
                rec["timestamp_delta"] += max_time + rng.uniform(1.0, 5.0)
                base.records.extend(inject.records)

        base.label = "mixed"
        base.sub_type = attack_type
        base.session_id = f"{sid}_mixed"
        return base


def real_samples_to_chain(sample: RealSample) -> "ApiCallChain":
    from src.sequence.chain_builder import ApiCallChain
    from src.ingestion.models import RequestRecord

    base_time = datetime.now()
    chain = ApiCallChain(session_id=sample.session_id)
    for rec in sample.records:
        delta = timedelta(seconds=rec.get("timestamp_delta", 0))
        chain.records.append(RequestRecord(
            timestamp=base_time + delta,
            method=rec.get("method", "GET"),
            path=rec.get("path", "/"),
            query_params=rec.get("query_params", {}),
            status_code=rec.get("status_code", 200),
            session_id=sample.session_id,
        ))
    return chain
