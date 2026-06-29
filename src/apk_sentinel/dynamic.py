from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse


def empty_dynamic_state() -> dict:
    return {"sessions": [], "captures": []}


def create_session(label: str, proxy_host: str = "127.0.0.1", proxy_port: int = 8088, notes: str = "") -> dict:
    created_at = datetime.now(timezone.utc).isoformat()
    session_id = created_at.replace(":", "").replace("-", "").split(".")[0]
    return {
        "id": session_id,
        "label": label or f"Dynamic session {created_at}",
        "created_at": created_at,
        "proxy_host": proxy_host,
        "proxy_port": proxy_port,
        "notes": notes,
        "status": "planned",
    }


def import_capture(path: str | Path, session_id: str | None = None) -> dict:
    capture_path = Path(path)
    raw = json.loads(capture_path.read_text(encoding="utf-8"))
    requests = _parse_har(raw) or _parse_mitmproxy_json(raw)
    return summarize_requests(requests, capture_path.name, session_id)


def summarize_requests(requests: list[dict], source_name: str, session_id: str | None = None) -> dict:
    domains = Counter(request["host"] for request in requests if request.get("host"))
    cleartext = [request for request in requests if request.get("scheme") == "http"]
    manipulated = [request for request in requests if request.get("applied_rules")]
    blocked = [request for request in requests if request.get("blocked")]
    methods = Counter(request.get("method", "UNKNOWN") for request in requests)
    statuses = Counter(str(request.get("status", "unknown")) for request in requests)
    created_at = datetime.now(timezone.utc).isoformat()
    return {
        "id": created_at.replace(":", "").replace("-", "").split(".")[0],
        "session_id": session_id,
        "created_at": created_at,
        "source_name": source_name,
        "request_count": len(requests),
        "domain_count": len(domains),
        "cleartext_count": len(cleartext),
        "manipulated_count": len(manipulated),
        "blocked_count": len(blocked),
        "top_domains": domains.most_common(20),
        "methods": dict(methods),
        "statuses": dict(statuses),
        "requests": requests[:500],
    }


def _parse_har(raw: object) -> list[dict]:
    if not isinstance(raw, dict):
        return []
    entries = raw.get("log", {}).get("entries", [])
    if not isinstance(entries, list):
        return []
    parsed: list[dict] = []
    for entry in entries:
        request = entry.get("request", {})
        response = entry.get("response", {})
        url = request.get("url", "")
        parsed_url = urlparse(url)
        parsed.append(
            {
                "method": request.get("method", "UNKNOWN"),
                "url": url,
                "scheme": parsed_url.scheme,
                "host": parsed_url.netloc,
                "path": parsed_url.path or "/",
                "status": response.get("status"),
                "mime_type": response.get("content", {}).get("mimeType"),
                "started_at": entry.get("startedDateTime"),
            }
        )
    return parsed


def _parse_mitmproxy_json(raw: object) -> list[dict]:
    flows = raw if isinstance(raw, list) else raw.get("flows", []) if isinstance(raw, dict) else []
    if not isinstance(flows, list):
        return []
    parsed: list[dict] = []
    for flow in flows:
        request = flow.get("request", {}) if isinstance(flow, dict) else {}
        response = flow.get("response", {}) if isinstance(flow, dict) else {}
        url = request.get("pretty_url") or request.get("url") or ""
        parsed_url = urlparse(url)
        parsed.append(
            {
                "method": request.get("method", "UNKNOWN"),
                "url": url,
                "scheme": parsed_url.scheme,
                "host": parsed_url.netloc,
                "path": parsed_url.path or "/",
                "status": response.get("status_code"),
                "mime_type": response.get("headers", {}).get("content-type") if isinstance(response.get("headers"), dict) else None,
                "started_at": request.get("timestamp_start"),
            }
        )
    return parsed
