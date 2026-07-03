import re
import json
import structlog
from datetime import datetime
from typing import Optional
from src.ingestion.models import RequestRecord

logger = structlog.get_logger()

NGINX_COMBINED_PATTERN = re.compile(
    r'(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<timestamp>[^\]]+)\]'
    r'\s+"(?P<method>\S+)\s+(?P<path>\S+)\s+\S+"'
    r'\s+(?P<status>\d+)'
    r'\s+(?P<size>\d+|-)'
    r'\s+"(?P<referer>[^"]*)"'
    r'\s+"(?P<ua>[^"]*)"'
)

APACHE_COMMON_PATTERN = re.compile(
    r'(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<timestamp>[^\]]+)\]'
    r'\s+"(?P<method>\S+)\s+(?P<path>\S+)\s+\S+"'
    r'\s+(?P<status>\d+)'
    r'\s+(?P<size>\d+|-)'
)

NGINX_TIMESTAMP_FMT = "%d/%b/%Y:%H:%M:%S %z"


def parse_nginx_line(line: str) -> Optional[RequestRecord]:
    m = NGINX_COMBINED_PATTERN.match(line.strip())
    if not m:
        return None
    try:
        ts = datetime.strptime(m.group("timestamp"), NGINX_TIMESTAMP_FMT)
    except ValueError:
        ts = datetime.now()

    path = m.group("path")
    query_params = {}
    if "?" in path:
        path, qs = path.split("?", 1)
        for pair in qs.split("&"):
            if "=" in pair:
                k, v = pair.split("=", 1)
                query_params[k] = v

    return RequestRecord(
        timestamp=ts,
        method=m.group("method"),
        path=path,
        query_params=query_params,
        status_code=int(m.group("status")),
        source_ip=m.group("ip"),
        session_id=m.group("ip"),
    )


def parse_apache_line(line: str) -> Optional[RequestRecord]:
    m = APACHE_COMMON_PATTERN.match(line.strip())
    if not m:
        return None
    try:
        ts = datetime.strptime(m.group("timestamp"), NGINX_TIMESTAMP_FMT)
    except ValueError:
        ts = datetime.now()

    path = m.group("path")
    query_params = {}
    if "?" in path:
        path, qs = path.split("?", 1)
        for pair in qs.split("&"):
            if "=" in pair:
                k, v = pair.split("=", 1)
                query_params[k] = v

    return RequestRecord(
        timestamp=ts,
        method=m.group("method"),
        path=path,
        query_params=query_params,
        status_code=int(m.group("status")),
        source_ip=m.group("ip"),
        session_id=m.group("ip"),
    )


def parse_json_log_line(line: str, field_mapping: Optional[dict] = None) -> Optional[RequestRecord]:
    if not field_mapping:
        field_mapping = {
            "timestamp": "timestamp",
            "method": "method",
            "path": "path",
            "status": "status_code",
            "ip": "source_ip",
        }
    try:
        data = json.loads(line.strip())
    except json.JSONDecodeError:
        return None

    mapped = {}
    for target, source in field_mapping.items():
        mapped[target] = data.get(source)

    ts = datetime.fromisoformat(mapped["timestamp"]) if mapped.get("timestamp") else datetime.now()
    path = mapped.get("path", "/")
    query_params = {}
    if "?" in path:
        path, qs = path.split("?", 1)
        for pair in qs.split("&"):
            if "=" in pair:
                k, v = pair.split("=", 1)
                query_params[k] = v

    return RequestRecord(
        timestamp=ts,
        method=mapped.get("method", "GET"),
        path=path,
        query_params=query_params,
        status_code=int(mapped["status"]) if mapped.get("status") else None,
        source_ip=mapped.get("ip"),
        session_id=mapped.get("ip"),
    )


def parse_log_line(line: str, fmt: str = "nginx", field_mapping: Optional[dict] = None) -> Optional[RequestRecord]:
    parsers = {
        "nginx": parse_nginx_line,
        "apache": parse_apache_line,
        "json": lambda l: parse_json_log_line(l, field_mapping),
    }
    parser = parsers.get(fmt)
    if not parser:
        logger.warning("unknown_log_format", fmt=fmt)
        return None
    return parser(line)
