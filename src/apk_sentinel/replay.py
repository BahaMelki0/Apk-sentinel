from __future__ import annotations

import http.client
import time
from datetime import datetime, timezone
from urllib.parse import urlsplit, urlunsplit

HOP_BY_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
}

REPLAY_STRIPPED_HEADERS = HOP_BY_HOP_HEADERS | {"content-length"}
MAX_REPLAY_RESPONSE_BYTES = 512 * 1024


def blank_replay_draft() -> dict:
    return {"raw_request": "GET / HTTP/1.1\r\nHost: example.test\r\n\r\n"}


def draft_from_request(request_record: dict | None) -> dict:
    if not request_record:
        return blank_replay_draft()

    return {"raw_request": request_record.get("raw_request_text") or raw_request_from_record(request_record)}


def raw_request_from_record(request_record: dict) -> str:
    method = (request_record.get("method") or "GET").upper()
    url = request_record.get("url") or "/"
    headers = request_record.get("request_headers") or {}
    body = request_record.get("request_body_text") or ""
    parsed = urlsplit(url)
    target = urlunsplit(("", "", parsed.path or "/", parsed.query, "")) if parsed.scheme else url
    lines = [f"{method} {target} HTTP/1.1"]
    if parsed.netloc and not _has_header(headers, "host"):
        lines.append(f"Host: {parsed.netloc}")
    if isinstance(headers, dict):
        for name, value in headers.items():
            if name.lower() in REPLAY_STRIPPED_HEADERS:
                continue
            lines.append(f"{name}: {value}")
    lines.append("")
    if body:
        lines.append(body)
    return "\r\n".join(lines)


def format_headers(headers: dict) -> str:
    lines: list[str] = []
    for name, value in headers.items():
        if name.lower() in REPLAY_STRIPPED_HEADERS:
            continue
        lines.append(f"{name}: {value}")
    return "\n".join(lines)


def replay_http_request(method: str, url: str, headers_text: str, body_text: str, timeout: int = 30) -> dict:
    parsed = urlsplit((url or "").strip())
    target = urlunsplit(("", "", parsed.path or "/", parsed.query, "")) if parsed.scheme else (url or "/")
    raw_request = f"{(method or 'GET').strip().upper()} {target} HTTP/1.1\r\n"
    if parsed.netloc:
        raw_request += f"Host: {parsed.netloc}\r\n"
    if headers_text:
        raw_request += headers_text.strip() + "\r\n"
    raw_request += "\r\n"
    raw_request += body_text or ""
    return replay_raw_http_request(raw_request, timeout=timeout)


def replay_raw_http_request(raw_request: str, timeout: int = 30) -> dict:
    started_at = _now()
    started = time.monotonic()
    raw_request = (raw_request or "").replace("\r\n", "\n").replace("\r", "\n")

    replay = {
        "id": started_at.replace(":", "").replace("-", "").split(".")[0],
        "created_at": started_at,
        "method": "",
        "url": "",
        "raw_request_text": raw_request,
        "request_headers_text": "",
        "request_body_text": "",
        "status": None,
        "reason": "",
        "duration_ms": 0,
        "response_headers": [],
        "response_headers_text": "",
        "response_body_text": "",
        "response_body_truncated": False,
        "response_bytes": 0,
        "error": None,
    }

    try:
        parsed_request = parse_raw_request(raw_request)
    except ValueError as exc:
        replay["error"] = str(exc)
        return replay

    method = parsed_request["method"]
    url = parsed_request["url"]
    headers = parsed_request["headers"]
    body_text = parsed_request["body"]
    body = body_text.encode("utf-8") if body_text else None

    replay["method"] = method
    replay["url"] = url
    replay["request_headers_text"] = format_headers(headers)
    replay["request_body_text"] = body_text

    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        replay["error"] = "Replay URL must be an absolute http:// or https:// URL."
        return replay

    connection: http.client.HTTPConnection | http.client.HTTPSConnection | None = None
    try:
        path = urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
        connection_cls = http.client.HTTPSConnection if parsed.scheme == "https" else http.client.HTTPConnection
        connection = connection_cls(parsed.hostname, parsed.port, timeout=timeout)
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        raw_body = b"" if method == "HEAD" else response.read(MAX_REPLAY_RESPONSE_BYTES + 1)
        response_body = raw_body[:MAX_REPLAY_RESPONSE_BYTES]

        replay["status"] = response.status
        replay["reason"] = response.reason
        replay["response_headers"] = response.getheaders()
        replay["response_headers_text"] = "\n".join(f"{name}: {value}" for name, value in response.getheaders())
        replay["response_body_text"] = response_body.decode("utf-8", errors="replace")
        replay["response_body_truncated"] = len(raw_body) > MAX_REPLAY_RESPONSE_BYTES
        replay["response_bytes"] = len(response_body)
    except Exception as exc:
        replay["error"] = str(exc)
    finally:
        replay["duration_ms"] = int((time.monotonic() - started) * 1000)
        if connection:
            connection.close()

    return replay


def parse_raw_request(raw_request: str) -> dict:
    if not raw_request.strip():
        raise ValueError("Raw request is empty.")

    head, separator, body = raw_request.partition("\n\n")
    if not separator:
        head = raw_request
        body = ""

    lines = head.splitlines()
    if not lines:
        raise ValueError("Raw request is empty.")

    request_line = lines[0].strip()
    parts = request_line.split()
    if len(parts) < 2:
        raise ValueError("First line must look like: METHOD /path HTTP/1.1")

    method = parts[0].upper()
    target = parts[1]
    headers_text = "\n".join(lines[1:])
    headers = parse_header_text(headers_text)
    host = _header_value(headers, "host")

    parsed_target = urlsplit(target)
    if parsed_target.scheme in {"http", "https"} and parsed_target.netloc:
        url = target
        if not host:
            headers["Host"] = parsed_target.netloc
    else:
        if not host:
            raise ValueError("Raw request needs a Host header when the request line uses a relative path.")
        scheme = "https" if host.endswith(":443") else "http"
        path = target if target.startswith("/") else f"/{target}"
        url = f"{scheme}://{host}{path}"

    return {"method": method, "url": url, "headers": headers, "body": body}


def parse_header_text(headers_text: str) -> dict[str, str]:
    headers: dict[str, str] = {}
    for line_number, line in enumerate((headers_text or "").splitlines(), start=1):
        if not line.strip():
            continue
        if ":" not in line:
            raise ValueError(f"Header line {line_number} is missing ':'.")
        name, value = line.split(":", 1)
        name = name.strip()
        if not name or any(char in name for char in "\r\n:"):
            raise ValueError(f"Header line {line_number} has an invalid name.")
        if name.lower() in REPLAY_STRIPPED_HEADERS:
            continue
        headers[name] = value.lstrip()
    return headers


def _has_header(headers: dict, expected: str) -> bool:
    return any(name.lower() == expected.lower() for name in headers)


def _header_value(headers: dict, expected: str) -> str:
    for name, value in headers.items():
        if name.lower() == expected.lower():
            return value
    return ""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
