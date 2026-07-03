import os
import re
import yaml
import json
import structlog
from typing import Optional, Any

logger = structlog.get_logger()


def _repair_content(content: str, path: str) -> str:
    content = content.replace("\t", " ")
    if path.endswith(".json"):
        content = re.sub(r",\s*([}\]])", r"\1", content)
    return content


def load_spec(path: str) -> Optional[dict]:
    if not os.path.exists(path):
        logger.error("spec_file_not_found", path=path)
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = f.read()
        content = _repair_content(raw, path)
        if path.endswith(".json"):
            return json.loads(content)
        return yaml.safe_load(content)
    except (yaml.YAMLError, json.JSONDecodeError) as e:
        logger.error("spec_parse_error", path=path, error=str(e))
        return None


def extract_security_info(spec: dict) -> dict:
    security_info = {}
    schemes = (spec.get("components") or {}).get("securitySchemes", {})
    security_info["global_schemes"] = {k: v.get("type", "unknown") for k, v in schemes.items()}

    paths = spec.get("paths", {})
    security_info["endpoints"] = {}
    for path, methods in paths.items():
        if not isinstance(methods, dict):
            continue
        for method, details in methods.items():
            if method in ("parameters",) or not isinstance(details, dict):
                continue
            endpoint_key = f"{method.upper()} {path}"
            endpoint_info = {
                "parameters": [],
                "security": details.get("security", spec.get("security", [])),
                "need_auth": False,
            }
            params = details.get("parameters", [])
            for p in params:
                param_info = {
                    "name": p.get("name"),
                    "in": p.get("in"),
                    "type": (p.get("schema") or {}).get("type", "string"),
                    "required": p.get("required", False),
                }
                endpoint_info["parameters"].append(param_info)
                if p.get("in") == "path":
                    endpoint_info["need_auth"] = True

            security_info["endpoints"][endpoint_key] = endpoint_info

    return security_info


def extract_path_parameters(spec: dict) -> dict[str, list[dict]]:
    result = {}
    paths = spec.get("paths", {})
    for path, methods in paths.items():
        if not isinstance(methods, dict):
            continue
        for method, details in methods.items():
            if method in ("parameters",) or not isinstance(details, dict):
                continue
            endpoint_key = f"{method.upper()} {path}"
            params = details.get("parameters", [])
            path_params = [
                {"name": p.get("name"), "type": (p.get("schema") or {}).get("type", "string")}
                for p in params
                if p.get("in") == "path"
            ]
            if path_params:
                result[endpoint_key] = path_params
    return result


def format_spec_summary(spec: dict) -> str:
    title = spec.get("info", {}).get("title", "Unknown API")
    version = spec.get("info", {}).get("version", "0.0.0")
    paths = spec.get("paths", {})
    endpoint_count = sum(
        1 for methods in paths.values()
        if isinstance(methods, dict)
        for m, d in methods.items()
        if m not in ("parameters",) and isinstance(d, dict)
    )
    return f"API: {title} v{version}, {endpoint_count} endpoints"


def format_spec_detail(spec: dict) -> str:
    lines = []
    paths = spec.get("paths", {})
    count = 0
    for path, methods in paths.items():
        if not isinstance(methods, dict):
            continue
        for method, details in methods.items():
            if method in ("parameters",) or not isinstance(details, dict):
                continue
            count += 1
            has_auth = bool(details.get("security", spec.get("security", [])))
            auth_tag = " [需认证]" if has_auth else ""
            params = details.get("parameters", [])
            path_params = [p.get("name") for p in params if p.get("in") == "path"]
            param_str = f" path_params=({','.join(path_params)})" if path_params else ""
            lines.append(f"  {method.upper()} {path}{auth_tag}{param_str}")
    title = spec.get("info", {}).get("title", "Unknown API")
    version = spec.get("info", {}).get("version", "0.0.0")
    return f"{title} v{version}, {count} 端点:\n" + "\n".join(lines)
