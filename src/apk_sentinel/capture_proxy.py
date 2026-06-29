from __future__ import annotations

import http.client
import json
import select
import socket
import ssl
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from socketserver import ThreadingMixIn
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from uuid import uuid4

from apk_sentinel.dynamic import summarize_requests
from apk_sentinel.replay import parse_raw_request
from apk_sentinel.tls_ca import ca_paths, ensure_host_certificate

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

MAX_CAPTURE_BODY_BYTES = 128 * 1024


class CaptureStore:
    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def append(self, record: dict) -> None:
        with self._lock:
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(record, sort_keys=True) + "\n")

    def records(self, limit: int | None = None) -> list[dict]:
        if not self.path.exists():
            return []
        with self._lock:
            lines = self.path.read_text(encoding="utf-8").splitlines()
        if limit is not None and limit > 0:
            lines = lines[-limit:]
        records: list[dict] = []
        for line in lines:
            if not line.strip():
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return records

    def count(self) -> int:
        if not self.path.exists():
            return 0
        with self._lock:
            return sum(1 for line in self.path.read_text(encoding="utf-8").splitlines() if line.strip())

    def clear(self) -> int:
        with self._lock:
            count = 0
            if self.path.exists():
                count = sum(1 for line in self.path.read_text(encoding="utf-8").splitlines() if line.strip())
            self.path.write_text("", encoding="utf-8")
            return count


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


@dataclass
class PendingIntercept:
    id: str
    created_at: str
    method: str
    url: str
    host: str
    path: str
    raw_request_text: str
    request_body_text: str
    request_body_truncated: bool
    request_bytes: int
    action: str | None = None
    edited_raw_request: str | None = None
    event: threading.Event = field(default_factory=threading.Event)

    def summary(self) -> dict:
        return {
            "id": self.id,
            "created_at": self.created_at,
            "method": self.method,
            "url": self.url,
            "host": self.host,
            "path": self.path,
            "raw_request_text": self.raw_request_text,
            "request_body_text": self.request_body_text,
            "request_body_truncated": self.request_body_truncated,
            "request_bytes": self.request_bytes,
        }


class CaptureProxyServer(ThreadedHTTPServer):
    def __init__(
        self,
        server_address: tuple[str, int],
        store: CaptureStore,
        rules: list[dict] | None = None,
        intercept_enabled: bool = False,
        ca_storage_dir: Path | None = None,
    ):
        super().__init__(server_address, CaptureProxyHandler)
        self.store = store
        self.rules = rules or []
        self.intercept_enabled = intercept_enabled
        self.ca_storage_dir = ca_storage_dir
        self.cert_cache_dir = store.path.parent / "certs"
        self._pending_intercepts: dict[str, PendingIntercept] = {}
        self._pending_lock = threading.Lock()

    def pending_intercepts(self) -> list[dict]:
        with self._pending_lock:
            return [item.summary() for item in self._pending_intercepts.values()]

    def queue_intercept(self, pending: PendingIntercept) -> PendingIntercept:
        with self._pending_lock:
            self._pending_intercepts[pending.id] = pending
        return pending

    def resolve_intercept(self, request_id: str, action: str, raw_request: str | None = None) -> bool:
        with self._pending_lock:
            pending = self._pending_intercepts.pop(request_id, None)
        if not pending:
            return False
        pending.action = action
        pending.edited_raw_request = raw_request
        pending.event.set()
        return True

    def forward_all_pending(self) -> int:
        with self._pending_lock:
            pending = list(self._pending_intercepts.values())
            self._pending_intercepts.clear()
        for item in pending:
            item.action = "forward"
            item.edited_raw_request = item.raw_request_text
            item.event.set()
        return len(pending)

    def release_pending(self, action: str = "drop") -> None:
        with self._pending_lock:
            pending = list(self._pending_intercepts.values())
            self._pending_intercepts.clear()
        for item in pending:
            item.action = action
            item.event.set()


class CaptureProxyHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_CONNECT(self) -> None:
        started_at = _now()
        host, port = _split_host_port(self.path, 443)
        status = 200
        error = None
        blocked = False
        intercept_action = "pass"
        started = time.monotonic()
        upstream = None
        raw_request_text = _raw_request_text(self, "")
        original_raw_request_text = None
        mitm_decrypted = False
        try:
            if _can_mitm(self.server, host):
                self.send_response(200, "Connection Established")
                self.end_headers()
                self.close_connection = True
                self._mitm_https(host, port)
                mitm_decrypted = True
                return

            if self.server.intercept_enabled:
                pending = self.server.queue_intercept(
                    PendingIntercept(
                        id=uuid4().hex,
                        created_at=_now(),
                        method="CONNECT",
                        url=f"https://{host}:{port}",
                        host=f"{host}:{port}",
                        path="",
                        raw_request_text=raw_request_text,
                        request_body_text="",
                        request_body_truncated=False,
                        request_bytes=0,
                    )
                )
                pending.event.wait()
                if pending.action != "forward":
                    intercept_action = "dropped"
                    blocked = True
                    status = 403
                    self.send_error(403, "Dropped by APK Sentinel interceptor")
                    return
                intercept_action = "forwarded"
                edited_raw_request = pending.edited_raw_request or raw_request_text
                if edited_raw_request != raw_request_text:
                    original_raw_request_text = raw_request_text
                host, port = _connect_target_from_raw(edited_raw_request, host, port)
                raw_request_text = edited_raw_request

            upstream = socket.create_connection((host, port), timeout=10)
            self.send_response(200, "Connection Established")
            self.end_headers()
            self._tunnel(upstream)
        except OSError as exc:
            status = 502
            error = str(exc)
            if not self.wfile.closed:
                self.send_error(502, "Proxy tunnel failed")
        finally:
            if mitm_decrypted:
                return
            if upstream:
                upstream.close()
            record = {
                "method": "CONNECT",
                "url": f"https://{host}:{port}",
                "scheme": "https",
                "host": f"{host}:{port}",
                "path": "",
                "status": status,
                "mime_type": None,
                "started_at": started_at,
                "duration_ms": int((time.monotonic() - started) * 1000),
                "request_bytes": 0,
                "response_bytes": 0,
                "request_headers": dict(self.headers),
                "request_body_text": "",
                "request_body_truncated": False,
                "raw_request_text": raw_request_text,
                "raw_request_truncated": False,
                "paused_by_interceptor": intercept_action in {"forwarded", "dropped"},
                "intercept_action": intercept_action,
                "error": error,
                "intercepted": False,
                "blocked": blocked,
            }
            if original_raw_request_text:
                record["original_raw_request_text"] = original_raw_request_text
            self.server.store.append(record)

    def do_DELETE(self) -> None:
        self._proxy_http()

    def do_GET(self) -> None:
        self._proxy_http()

    def do_HEAD(self) -> None:
        self._proxy_http()

    def do_OPTIONS(self) -> None:
        self._proxy_http()

    def do_PATCH(self) -> None:
        self._proxy_http()

    def do_POST(self) -> None:
        self._proxy_http()

    def do_PUT(self) -> None:
        self._proxy_http()

    def log_message(self, _format: str, *_args) -> None:
        return

    def _proxy_http(self) -> None:
        started_at = _now()
        started = time.monotonic()
        method = self.command
        body = self._read_body()
        target = _target_from_request(self)
        status = 502
        response_size = 0
        response_body = b""
        response_headers: list[tuple[str, str]] = []
        mime_type = None
        error = None
        blocked = False
        applied_rules: list[dict] = []
        request_headers: dict[str, str] = {}
        request_preview = _body_preview(body)
        raw_request_text = _raw_request_text(self, request_preview["text"])
        original_raw_request_text = None
        intercept_action = "pass"

        try:
            headers = _forward_headers(self.headers, target["host_header"])
            request_headers = dict(headers)
            if self.server.intercept_enabled:
                pending = self.server.queue_intercept(
                    PendingIntercept(
                        id=uuid4().hex,
                        created_at=_now(),
                        method=method,
                        url=target["url"],
                        host=target["host_header"],
                        path=target["path"],
                        raw_request_text=raw_request_text,
                        request_body_text=request_preview["text"],
                        request_body_truncated=request_preview["truncated"],
                        request_bytes=len(body),
                    )
                )
                pending.event.wait()
                if pending.action != "forward":
                    intercept_action = "dropped"
                    blocked = True
                    status = 403
                    response_body = b"Dropped by APK Sentinel interceptor."
                    response_headers = [
                        ("content-type", "text/plain; charset=utf-8"),
                        ("content-length", str(len(response_body))),
                    ]
                    response_size = len(response_body)
                    mime_type = "text/plain"
                    self.send_response(status, "Dropped by APK Sentinel")
                    self.send_header("content-type", "text/plain; charset=utf-8")
                    self.send_header("content-length", str(response_size))
                    self.send_header("Connection", "close")
                    self.end_headers()
                    self.wfile.write(response_body)
                    return

                intercept_action = "forwarded"
                edited_raw_request = pending.edited_raw_request or raw_request_text
                if edited_raw_request != raw_request_text:
                    original_raw_request_text = raw_request_text
                parsed_request = parse_raw_request(edited_raw_request)
                method = parsed_request["method"]
                target = _target_from_url(parsed_request["url"])
                body_text = parsed_request["body"]
                body = body_text.encode("utf-8") if body_text else b""
                request_preview = _body_preview(body)
                raw_request_text = edited_raw_request
                headers = _forward_header_dict(parsed_request["headers"], target["host_header"])
                request_headers = dict(headers)

            applied_rules, block = _apply_rules(self.server.rules, method, target, headers)
            request_headers = dict(headers)
            if block:
                blocked = True
                status = block["status"]
                response_body = block["body"].encode("utf-8", errors="replace")
                response_headers = [
                    ("content-type", "text/plain; charset=utf-8"),
                    ("content-length", str(len(response_body))),
                ]
                response_size = len(response_body)
                mime_type = "text/plain"
                self.send_response(status, "Blocked by APK Sentinel")
                self.send_header("content-type", "text/plain; charset=utf-8")
                self.send_header("content-length", str(response_size))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(response_body)
                return

            connection = http.client.HTTPConnection(target["hostname"], target["port"], timeout=20)
            connection.request(method, target["request_target"], body=body, headers=headers)
            response = connection.getresponse()
            response_body = b"" if method == "HEAD" else response.read()
            status = response.status
            response_size = len(response_body)
            mime_type = response.getheader("content-type")
            response_headers = response.getheaders()

            self.send_response(response.status, response.reason)
            for header, value in response.getheaders():
                if header.lower() in HOP_BY_HOP_HEADERS:
                    continue
                self.send_header(header, value)
            self.send_header("Connection", "close")
            self.end_headers()
            if response_body:
                self.wfile.write(response_body)
            connection.close()
        except Exception as exc:
            error = str(exc)
            try:
                self.send_error(502, "Proxy request failed")
            except OSError:
                pass
        finally:
            response_preview = _body_preview(response_body)
            record = {
                    "method": method,
                    "url": target["url"],
                    "scheme": "http",
                    "host": target["host_header"],
                    "path": target["path"],
                    "status": status,
                    "mime_type": mime_type,
                    "started_at": started_at,
                    "duration_ms": int((time.monotonic() - started) * 1000),
                    "request_bytes": len(body),
                    "response_bytes": response_size,
                    "request_headers": request_headers,
                    "request_body_text": request_preview["text"],
                    "request_body_truncated": request_preview["truncated"],
                    "raw_request_text": raw_request_text,
                    "raw_request_truncated": request_preview["truncated"],
                    "paused_by_interceptor": intercept_action in {"forwarded", "dropped"},
                    "intercept_action": intercept_action,
                    "response_headers": response_headers,
                    "response_body_text": response_preview["text"],
                    "response_body_truncated": response_preview["truncated"],
                    "error": error,
                    "intercepted": True,
                    "applied_rules": applied_rules,
                    "blocked": blocked,
                }
            if original_raw_request_text:
                record["original_raw_request_text"] = original_raw_request_text
            self.server.store.append(record)

    def _mitm_https(self, host: str, port: int) -> None:
        cert_paths = ensure_host_certificate(self.server.ca_storage_dir, self.server.cert_cache_dir, host)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert_paths["cert"], cert_paths["key"])
        try:
            context.set_alpn_protocols(["http/1.1"])
        except NotImplementedError:
            pass

        client_tls = context.wrap_socket(self.connection, server_side=True)
        client_tls.settimeout(30)
        try:
            reader = client_tls.makefile("rb")
            request_data = _read_inner_http_request(reader, host, port)
            if request_data is None:
                return
            self._proxy_https_inner_request(client_tls, request_data)
        finally:
            try:
                client_tls.close()
            except OSError:
                pass

    def _proxy_https_inner_request(self, client_tls: ssl.SSLSocket, request_data: dict) -> None:
        started_at = _now()
        started = time.monotonic()
        method = request_data["method"]
        body = request_data["body"]
        target = request_data["target"]
        headers = _forward_header_dict(request_data["headers"], target["host_header"])
        request_headers = dict(headers)
        status = 502
        reason = "Proxy Error"
        response_size = 0
        response_body = b""
        response_headers: list[tuple[str, str]] = []
        mime_type = None
        error = None
        blocked = False
        applied_rules: list[dict] = []
        request_preview = _body_preview(body)
        raw_request_text = _raw_request_from_parts(method, target["url"], request_data["headers"], request_preview["text"])
        original_raw_request_text = None
        intercept_action = "pass"
        connection: http.client.HTTPSConnection | None = None

        try:
            if self.server.intercept_enabled:
                pending = self.server.queue_intercept(
                    PendingIntercept(
                        id=uuid4().hex,
                        created_at=_now(),
                        method=method,
                        url=target["url"],
                        host=target["host_header"],
                        path=target["path"],
                        raw_request_text=raw_request_text,
                        request_body_text=request_preview["text"],
                        request_body_truncated=request_preview["truncated"],
                        request_bytes=len(body),
                    )
                )
                pending.event.wait()
                if pending.action != "forward":
                    intercept_action = "dropped"
                    blocked = True
                    status = 403
                    reason = "Dropped by APK Sentinel"
                    response_body = b"Dropped by APK Sentinel interceptor."
                    response_headers = [
                        ("content-type", "text/plain; charset=utf-8"),
                        ("content-length", str(len(response_body))),
                    ]
                    response_size = len(response_body)
                    mime_type = "text/plain"
                    _write_inner_http_response(client_tls, status, reason, response_headers, response_body)
                    return

                intercept_action = "forwarded"
                edited_raw_request = pending.edited_raw_request or raw_request_text
                if edited_raw_request != raw_request_text:
                    original_raw_request_text = raw_request_text
                parsed_request = _parse_edited_https_request(edited_raw_request)
                method = parsed_request["method"]
                target = _target_from_https_url(parsed_request["url"])
                body_text = parsed_request["body"]
                body = body_text.encode("utf-8") if body_text else b""
                request_preview = _body_preview(body)
                raw_request_text = edited_raw_request
                headers = _forward_header_dict(parsed_request["headers"], target["host_header"])
                request_headers = dict(headers)

            applied_rules, block = _apply_rules(self.server.rules, method, target, headers)
            request_headers = dict(headers)
            if block:
                blocked = True
                status = block["status"]
                reason = "Blocked by APK Sentinel"
                response_body = block["body"].encode("utf-8", errors="replace")
                response_headers = [
                    ("content-type", "text/plain; charset=utf-8"),
                    ("content-length", str(len(response_body))),
                ]
                response_size = len(response_body)
                mime_type = "text/plain"
                _write_inner_http_response(client_tls, status, reason, response_headers, response_body)
                return

            connection = http.client.HTTPSConnection(
                target["hostname"],
                target["port"],
                timeout=20,
                context=ssl._create_unverified_context(),
            )
            connection.request(method, target["request_target"], body=body, headers=headers)
            response = connection.getresponse()
            response_body = b"" if method == "HEAD" else response.read()
            status = response.status
            reason = response.reason
            response_size = len(response_body)
            mime_type = response.getheader("content-type")
            response_headers = response.getheaders()
            _write_inner_http_response(client_tls, status, reason, response_headers, response_body)
        except Exception as exc:
            error = str(exc)
            response_body = b"Proxy HTTPS request failed."
            response_headers = [
                ("content-type", "text/plain; charset=utf-8"),
                ("content-length", str(len(response_body))),
            ]
            response_size = len(response_body)
            try:
                _write_inner_http_response(client_tls, 502, "Proxy HTTPS request failed", response_headers, response_body)
            except OSError:
                pass
        finally:
            if connection:
                connection.close()
            response_preview = _body_preview(response_body)
            record = {
                "method": method,
                "url": target["url"],
                "scheme": "https",
                "host": target["host_header"],
                "path": target["path"],
                "status": status,
                "mime_type": mime_type,
                "started_at": started_at,
                "duration_ms": int((time.monotonic() - started) * 1000),
                "request_bytes": len(body),
                "response_bytes": response_size,
                "request_headers": request_headers,
                "request_body_text": request_preview["text"],
                "request_body_truncated": request_preview["truncated"],
                "raw_request_text": raw_request_text,
                "raw_request_truncated": request_preview["truncated"],
                "paused_by_interceptor": intercept_action in {"forwarded", "dropped"},
                "intercept_action": intercept_action,
                "response_headers": response_headers,
                "response_body_text": response_preview["text"],
                "response_body_truncated": response_preview["truncated"],
                "error": error,
                "intercepted": True,
                "tls_decrypted": True,
                "applied_rules": applied_rules,
                "blocked": blocked,
            }
            if original_raw_request_text:
                record["original_raw_request_text"] = original_raw_request_text
            self.server.store.append(record)

    def _read_body(self) -> bytes:
        try:
            length = int(self.headers.get("content-length", "0"))
        except ValueError:
            length = 0
        if length <= 0:
            return b""
        return self.rfile.read(length)

    def _tunnel(self, upstream: socket.socket) -> None:
        sockets = [self.connection, upstream]
        while True:
            readable, _, exceptional = select.select(sockets, [], sockets, 30)
            if exceptional or not readable:
                break
            for source in readable:
                destination = upstream if source is self.connection else self.connection
                data = source.recv(8192)
                if not data:
                    return
                destination.sendall(data)


@dataclass
class ProxyInstance:
    key: str
    case_id: str
    session_id: str
    host: str
    port: int
    started_at: str
    server: CaptureProxyServer
    thread: threading.Thread
    store: CaptureStore
    rules: list[dict]


class CaptureProxyManager:
    def __init__(self):
        self._instances: dict[str, ProxyInstance] = {}
        self._lock = threading.Lock()

    def start(
        self,
        case_id: str,
        session_id: str,
        host: str,
        port: int,
        case_dir: Path,
        rules: list[dict] | None = None,
        intercept_enabled: bool = False,
        ca_storage_dir: Path | None = None,
    ) -> ProxyInstance:
        key = _key(case_id, session_id)
        with self._lock:
            if key in self._instances:
                return self._instances[key]

            store = CaptureStore(case_dir / "proxy" / f"{session_id}.jsonl")
            server = CaptureProxyServer((host, port), store, rules, intercept_enabled, ca_storage_dir)
            actual_host, actual_port = server.server_address
            thread = threading.Thread(target=server.serve_forever, name=f"apk-sentinel-proxy-{session_id}", daemon=True)
            thread.start()
            instance = ProxyInstance(
                key=key,
                case_id=case_id,
                session_id=session_id,
                host=actual_host,
                port=actual_port,
                started_at=_now(),
                server=server,
                thread=thread,
                store=store,
                rules=rules or [],
            )
            self._instances[key] = instance
            return instance

    def stop(self, case_id: str, session_id: str) -> dict | None:
        key = _key(case_id, session_id)
        with self._lock:
            instance = self._instances.pop(key, None)
        if not instance:
            return None
        instance.server.release_pending("drop")
        instance.server.shutdown()
        instance.server.server_close()
        instance.thread.join(timeout=5)
        records = instance.store.records()
        return summarize_requests(records, f"built-in-proxy-{session_id}.json", session_id)

    def status(self, case_id: str, session_id: str) -> dict:
        key = _key(case_id, session_id)
        with self._lock:
            instance = self._instances.get(key)
        if not instance:
            return {"running": False}
        pending = instance.server.pending_intercepts()
        return {
            "running": True,
            "host": instance.host,
            "port": instance.port,
            "started_at": instance.started_at,
            "request_count": instance.store.count(),
            "rule_count": len(instance.rules),
            "intercept_enabled": instance.server.intercept_enabled,
            "pending_count": len(pending),
        }

    def set_intercept_enabled(self, case_id: str, enabled: bool, session_id: str | None = None) -> int:
        updated = 0
        with self._lock:
            instances = list(self._instances.values())
        for instance in instances:
            if instance.case_id != case_id:
                continue
            if session_id and instance.session_id != session_id:
                continue
            instance.server.intercept_enabled = enabled
            updated += 1
        return updated

    def pending_intercepts(self, case_id: str) -> list[dict]:
        pending: list[dict] = []
        with self._lock:
            instances = list(self._instances.values())
        for instance in instances:
            if instance.case_id != case_id:
                continue
            for item in instance.server.pending_intercepts():
                item["session_id"] = instance.session_id
                item["proxy"] = f"{instance.host}:{instance.port}"
                pending.append(item)
        return sorted(pending, key=lambda item: item.get("created_at", ""))

    def live_captures(self, case_id: str) -> list[dict]:
        captures: list[dict] = []
        with self._lock:
            instances = list(self._instances.values())
        for instance in instances:
            if instance.case_id != case_id:
                continue
            total_count = instance.store.count()
            records = instance.store.records(limit=300)
            if not records:
                continue
            capture = summarize_requests(records, f"live-proxy-{instance.session_id}.json", instance.session_id)
            capture["id"] = f"live-{instance.session_id}"
            capture["source_name"] = f"live-proxy-{instance.session_id}.json"
            capture["live"] = True
            capture["request_count"] = max(total_count, len(records))
            capture["windowed"] = total_count > len(records)
            captures.append(capture)
        return captures

    def resolve_intercept(self, case_id: str, request_id: str, action: str, raw_request: str | None = None) -> bool:
        with self._lock:
            instances = list(self._instances.values())
        for instance in instances:
            if instance.case_id != case_id:
                continue
            if instance.server.resolve_intercept(request_id, action, raw_request):
                return True
        return False

    def forward_all_intercepts(self, case_id: str) -> int:
        forwarded = 0
        with self._lock:
            instances = list(self._instances.values())
        for instance in instances:
            if instance.case_id == case_id:
                forwarded += instance.server.forward_all_pending()
        return forwarded

    def clear_history(self, case_id: str, session_id: str | None = None) -> int:
        cleared = 0
        with self._lock:
            instances = list(self._instances.values())
        for instance in instances:
            if instance.case_id != case_id:
                continue
            if session_id and instance.session_id != session_id:
                continue
            cleared += instance.store.clear()
        return cleared


def _target_from_request(handler: CaptureProxyHandler) -> dict:
    raw_target = handler.path
    if raw_target.startswith("http://"):
        parsed = urlsplit(raw_target)
    else:
        host = handler.headers.get("host", "")
        parsed = urlsplit(f"http://{host}{raw_target}")

    if parsed.scheme != "http" or not parsed.hostname:
        raise ValueError(f"unsupported proxy target: {raw_target}")

    port = parsed.port or 80
    host_header = parsed.netloc
    path = urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
    return {
        "url": urlunsplit(("http", parsed.netloc, parsed.path or "/", parsed.query, "")),
        "hostname": parsed.hostname,
        "port": port,
        "host_header": host_header,
        "path": path,
        "request_target": path,
    }


def _target_from_url(url: str) -> dict:
    parsed = urlsplit(url)
    if parsed.scheme != "http" or not parsed.hostname:
        raise ValueError(f"unsupported proxy target: {url}")
    port = parsed.port or 80
    host_header = parsed.netloc
    return {
        "url": urlunsplit(("http", parsed.netloc, parsed.path or "/", parsed.query, "")),
        "hostname": parsed.hostname,
        "port": port,
        "host_header": host_header,
        "path": urlunsplit(("", "", parsed.path or "/", parsed.query, "")),
        "request_target": urlunsplit(("", "", parsed.path or "/", parsed.query, "")),
    }


def _target_from_https_url(url: str) -> dict:
    parsed = urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise ValueError(f"unsupported HTTPS proxy target: {url}")
    port = parsed.port or 443
    host_header = parsed.netloc
    return {
        "url": urlunsplit(("https", parsed.netloc, parsed.path or "/", parsed.query, "")),
        "hostname": parsed.hostname,
        "port": port,
        "host_header": host_header,
        "path": urlunsplit(("", "", parsed.path or "/", parsed.query, "")),
        "request_target": urlunsplit(("", "", parsed.path or "/", parsed.query, "")),
    }


def _target_from_inner_https_request(target: str, headers: dict[str, str], tunnel_host: str, tunnel_port: int) -> dict:
    parsed_target = urlsplit(target)
    if parsed_target.scheme == "https" and parsed_target.netloc:
        return _target_from_https_url(target)

    host_header = _header_value(headers, "host") or _host_header(tunnel_host, tunnel_port)
    parsed_host = urlsplit(f"//{host_header}")
    hostname = parsed_host.hostname or tunnel_host
    port = parsed_host.port or tunnel_port or 443
    path = target if target.startswith("/") else f"/{target}"
    return {
        "url": urlunsplit(("https", host_header, urlsplit(path).path or "/", urlsplit(path).query, "")),
        "hostname": hostname,
        "port": port,
        "host_header": host_header,
        "path": urlunsplit(("", "", urlsplit(path).path or "/", urlsplit(path).query, "")),
        "request_target": urlunsplit(("", "", urlsplit(path).path or "/", urlsplit(path).query, "")),
    }


def _read_inner_http_request(reader, tunnel_host: str, tunnel_port: int) -> dict | None:
    request_line_bytes = reader.readline(65536)
    if not request_line_bytes:
        return None
    request_line = request_line_bytes.decode("iso-8859-1", errors="replace").strip()
    if not request_line:
        return None
    parts = request_line.split()
    if len(parts) < 2:
        raise ValueError("Invalid HTTPS request line inside tunnel.")

    header_lines: list[str] = []
    while True:
        line = reader.readline(65536)
        if line in {b"\r\n", b"\n", b""}:
            break
        header_lines.append(line.decode("iso-8859-1", errors="replace").rstrip("\r\n"))

    headers = _headers_from_lines(header_lines)
    body = _read_inner_body(reader, headers)
    method = parts[0].upper()
    target = _target_from_inner_https_request(parts[1], headers, tunnel_host, tunnel_port)
    return {
        "method": method,
        "target": target,
        "headers": headers,
        "body": body,
    }


def _read_inner_body(reader, headers: dict[str, str]) -> bytes:
    try:
        length = int(_header_value(headers, "content-length") or "0")
    except ValueError:
        length = 0
    if length <= 0:
        return b""
    return reader.read(length)


def _headers_from_lines(lines: list[str]) -> dict[str, str]:
    headers: dict[str, str] = {}
    for line in lines:
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        name = name.strip()
        if name:
            headers[name] = value.lstrip()
    return headers


def _parse_edited_https_request(raw_request: str) -> dict:
    parsed = parse_raw_request(raw_request)
    url = parsed["url"]
    split = urlsplit(url)
    if split.scheme == "http":
        url = urlunsplit(("https", split.netloc, split.path or "/", split.query, ""))
    parsed["url"] = url
    return parsed


def _raw_request_from_parts(method: str, url: str, headers: dict[str, str], body_text: str) -> str:
    lines = [f"{method} {url} HTTP/1.1"]
    for name, value in headers.items():
        if name.lower() in {"content-length"}:
            continue
        lines.append(f"{name}: {value}")
    lines.append("")
    if body_text:
        lines.append(body_text)
    return "\r\n".join(lines)


def _write_inner_http_response(sock: ssl.SSLSocket, status: int, reason: str, headers: list[tuple[str, str]], body: bytes) -> None:
    lines = [f"HTTP/1.1 {status} {reason or ''}".rstrip()]
    sent_content_length = False
    for header, value in headers:
        lower = header.lower()
        if lower in HOP_BY_HOP_HEADERS:
            continue
        if lower == "content-length":
            sent_content_length = True
            value = str(len(body))
        lines.append(f"{header}: {value}")
    if not sent_content_length:
        lines.append(f"Content-Length: {len(body)}")
    lines.append("Connection: close")
    lines.append("")
    lines.append("")
    sock.sendall("\r\n".join(lines).encode("iso-8859-1", errors="replace"))
    if body:
        sock.sendall(body)


def _can_mitm(server: CaptureProxyServer, host: str) -> bool:
    storage_dir = getattr(server, "ca_storage_dir", None)
    if storage_dir is None:
        return False
    paths = ca_paths(storage_dir)
    return paths["cert"].exists() and paths["key"].exists() and bool(host)


def _host_header(host: str, port: int) -> str:
    return host if port == 443 else f"{host}:{port}"


def _header_value(headers: dict[str, str], expected: str) -> str:
    for name, value in headers.items():
        if name.lower() == expected.lower():
            return value
    return ""


def _forward_headers(headers, host_header: str) -> dict[str, str]:
    forwarded: dict[str, str] = {}
    for header, value in headers.items():
        lower = header.lower()
        if lower in HOP_BY_HOP_HEADERS or lower in {"host", "content-length"}:
            continue
        forwarded[header] = value
    forwarded["Host"] = host_header
    forwarded["Connection"] = "close"
    return forwarded


def _forward_header_dict(headers: dict[str, str], host_header: str) -> dict[str, str]:
    forwarded: dict[str, str] = {}
    for header, value in headers.items():
        lower = header.lower()
        if lower in HOP_BY_HOP_HEADERS or lower == "content-length":
            continue
        forwarded[header] = value
    if not any(header.lower() == "host" for header in forwarded):
        forwarded["Host"] = host_header
    forwarded["Connection"] = "close"
    return forwarded


def _apply_rules(
    rules: list[dict],
    method: str,
    target: dict,
    headers: dict[str, str],
) -> tuple[list[dict], dict | None]:
    applied: list[dict] = []
    block: dict | None = None

    for rule in rules:
        if not rule.get("enabled", True) or not _rule_matches(rule, method, target):
            continue

        action = rule.get("action")
        applied.append(
            {
                "id": rule.get("id"),
                "name": rule.get("name") or action,
                "action": action,
            }
        )

        if action == "set_header":
            header_name = rule.get("header_name", "").strip()
            if header_name:
                headers[header_name] = rule.get("header_value", "")
        elif action == "remove_header":
            header_name = rule.get("header_name", "").strip().lower()
            for existing in list(headers):
                if existing.lower() == header_name:
                    headers.pop(existing, None)
        elif action == "add_query":
            _add_query_param(target, rule.get("query_name", ""), rule.get("query_value", ""))
        elif action == "block_request":
            block = {
                "status": _status_code(rule.get("block_status")),
                "body": rule.get("block_body") or "Blocked by APK Sentinel proxy rule.",
            }
            break

    return applied, block


def _rule_matches(rule: dict, method: str, target: dict) -> bool:
    match_method = (rule.get("match_method") or "").strip().upper()
    if match_method and match_method != "ANY" and match_method != method.upper():
        return False

    host = target["host_header"].lower()
    path = target["path"].lower()
    host_match = (rule.get("match_host") or "").strip().lower()
    path_match = (rule.get("match_path") or "").strip().lower()
    return (not host_match or host_match in host) and (not path_match or path_match in path)


def _add_query_param(target: dict, name: str, value: str) -> None:
    name = name.strip()
    if not name:
        return
    parsed = urlsplit(target["url"])
    params = parse_qsl(parsed.query, keep_blank_values=True)
    params.append((name, value))
    new_query = urlencode(params)
    target["url"] = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, new_query, ""))
    target["request_target"] = urlunsplit(("", "", parsed.path or "/", new_query, ""))


def _status_code(value) -> int:
    try:
        status = int(value)
    except (TypeError, ValueError):
        return 403
    return status if 100 <= status <= 599 else 403


def _body_preview(data: bytes) -> dict:
    preview = data[:MAX_CAPTURE_BODY_BYTES]
    return {
        "text": preview.decode("utf-8", errors="replace"),
        "truncated": len(data) > MAX_CAPTURE_BODY_BYTES,
    }


def _raw_request_text(handler: CaptureProxyHandler, body_text: str) -> str:
    lines = [handler.requestline or f"{handler.command} {handler.path} {handler.request_version}"]
    for name, value in handler.headers.items():
        lines.append(f"{name}: {value}")
    lines.append("")
    if body_text:
        lines.append(body_text)
    return "\r\n".join(lines)


def _connect_target_from_raw(raw_request: str, fallback_host: str, fallback_port: int) -> tuple[str, int]:
    first_line = (raw_request or "").replace("\r\n", "\n").replace("\r", "\n").split("\n", 1)[0]
    parts = first_line.split()
    if len(parts) < 2 or parts[0].upper() != "CONNECT":
        return fallback_host, fallback_port
    return _split_host_port(parts[1], fallback_port)


def _split_host_port(value: str, default_port: int) -> tuple[str, int]:
    if ":" not in value:
        return value, default_port
    host, port = value.rsplit(":", 1)
    try:
        return host, int(port)
    except ValueError:
        return value, default_port


def _key(case_id: str, session_id: str) -> str:
    return f"{case_id}:{session_id}"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
