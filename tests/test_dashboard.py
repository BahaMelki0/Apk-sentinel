from __future__ import annotations

import http.client
import io
import json
import re
import socket
import ssl
import sys
import tempfile
import threading
import time
import unittest
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

try:
    from apk_sentinel.dashboard import create_app
    from apk_sentinel.tls_ca import ca_paths, cryptography_available, ensure_ca, ensure_host_certificate
except ImportError as exc:  # pragma: no cover - only used when Flask is unavailable.
    create_app = None
    cryptography_available = lambda: False
    FLASK_IMPORT_ERROR = exc
else:
    FLASK_IMPORT_ERROR = None


DASHBOARD_MANIFEST = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.dashboard">
    <uses-sdk android:minSdkVersion="23" android:targetSdkVersion="35" />
    <uses-permission android:name="android.permission.CAMERA" />
    <application android:usesCleartextTraffic="true">
        <activity android:name=".MainActivity" android:exported="true" />
    </application>
</manifest>
"""


@unittest.skipIf(create_app is None, f"Flask unavailable: {FLASK_IMPORT_ERROR}")
class DashboardTests(unittest.TestCase):
    def test_upload_case_and_preview_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            app = create_app(storage_dir=Path(temp_dir) / "store")
            app.config.update(TESTING=True)
            client = app.test_client()

            response = client.post(
                "/cases",
                data={"apk": (io.BytesIO(_apk_bytes()), "dashboard.apk")},
                content_type="multipart/form-data",
            )

            self.assertEqual(response.status_code, 302)
            location = response.headers["Location"]
            case_id = location.rstrip("/").split("/")[-1]

            overview = client.get(location)
            self.assertEqual(overview.status_code, 200)
            self.assertIn(b"com.example.dashboard", overview.data)
            self.assertIn(b"Static Posture", overview.data)
            self.assertIn(b"Vuln Intel: No matches", overview.data)
            self.assertIn(b"Dependencies", overview.data)

            _write_test_vuln_db(Path(app.config["STORAGE_DIR"]))

            global_intel = client.get("/intelligence")
            self.assertEqual(global_intel.status_code, 200)
            self.assertIn(b"Vulnerability Intelligence", global_intel.data)
            self.assertIn(b"com.squareup.okhttp3:okhttp", global_intel.data)

            case_intel = client.get(f"/cases/{case_id}/intelligence")
            self.assertEqual(case_intel.status_code, 200)
            self.assertIn(b"CVE-2026-0001", case_intel.data)
            self.assertIn(b"Cached Vulnerability Matches", case_intel.data)

            settings_page = client.get("/settings")
            self.assertEqual(settings_page.status_code, 200)
            self.assertIn(b"Storage Path", settings_page.data)
            self.assertIn(b"Default Proxy Port", settings_page.data)

            save_settings = client.post(
                "/settings",
                data={
                    "report_author": "Unit Tester",
                    "default_proxy_host": "127.0.0.1",
                    "default_proxy_port": "9090",
                },
            )
            self.assertEqual(save_settings.status_code, 302)
            report_defaults = client.get(f"/cases/{case_id}/report")
            self.assertIn(b"Unit Tester", report_defaults.data)
            proxy_defaults = client.get("/proxy")
            self.assertIn(b"9090", proxy_defaults.data)

            about = client.get("/about")
            self.assertEqual(about.status_code, 200)
            self.assertIn(b"About APK Sentinel", about.data)
            self.assertIn(b"Version", about.data)

            missing = client.get("/missing")
            self.assertEqual(missing.status_code, 404)
            self.assertIn(b"Not Found", missing.data)

            save_notes = client.post(
                f"/cases/{case_id}/notes",
                data={"case_notes": "scope: authorized dashboard smoke", "next": f"/cases/{case_id}"},
            )
            self.assertEqual(save_notes.status_code, 302)
            overview = client.get(location)
            self.assertIn(b"scope: authorized dashboard smoke", overview.data)
            self.assertIn(b"Vuln Matches", overview.data)
            self.assertIn(b"External Vuln Findings", overview.data)

            files = client.get(f"/cases/{case_id}/files", query_string={"path": "AndroidManifest.xml"})
            self.assertEqual(files.status_code, 200)
            self.assertIn(b"Extracted Content", files.data)
            self.assertIn(b"AndroidManifest.xml", files.data)
            self.assertIn(b"com.example.dashboard", files.data)
            self.assertIn(b"APK root", files.data)

            root_files = client.get(f"/cases/{case_id}/files")
            self.assertEqual(root_files.status_code, 200)
            self.assertIn(b"assets/", root_files.data)
            self.assertIn(b"classes.dex", root_files.data)

            assets_folder = client.get(f"/cases/{case_id}/files", query_string={"dir": "assets"})
            self.assertEqual(assets_folder.status_code, 200)
            self.assertIn(b"config.json", assets_folder.data)
            self.assertNotIn(b"classes.dex", assets_folder.data)

            strings = client.get(
                f"/cases/{case_id}/files",
                query_string={"path": "assets/config.json", "view": "strings"},
            )
            self.assertEqual(strings.status_code, 200)
            self.assertIn(b"api.example.test", strings.data)
            self.assertIn(b"Mark Reviewed", strings.data)

            reviewed = client.post(
                f"/cases/{case_id}/files/review",
                data={"path": "assets/config.json", "view": "strings", "kind": "all", "deep": "0"},
            )
            self.assertEqual(reviewed.status_code, 302)
            reviewed_page = client.get(
                f"/cases/{case_id}/files",
                query_string={"path": "assets/config.json", "view": "strings"},
            )
            self.assertIn(b"reviewed", reviewed_page.data)

            deep_search = client.get(
                f"/cases/{case_id}/files",
                query_string={"q": "api.example.test", "deep": "1"},
            )
            self.assertEqual(deep_search.status_code, 200)
            self.assertIn(b"assets/config.json", deep_search.data)

            indicators = client.get(f"/cases/{case_id}/indicators")
            self.assertEqual(indicators.status_code, 200)
            self.assertIn(b"Secrets & Indicators", indicators.data)
            self.assertIn(b"Google API key", indicators.data)
            self.assertIn(b"Proof Hash", indicators.data)

            session = client.post(
                f"/cases/{case_id}/dynamic/sessions",
                data={"label": "Login smoke", "proxy_host": "127.0.0.1", "proxy_port": "8088"},
            )
            self.assertEqual(session.status_code, 302)

            capture = client.post(
                f"/cases/{case_id}/dynamic/captures",
                data={"capture": (io.BytesIO(_har_bytes()), "capture.har")},
                content_type="multipart/form-data",
            )
            self.assertEqual(capture.status_code, 302)

            dynamic = client.get(f"/cases/{case_id}/dynamic")
            self.assertEqual(dynamic.status_code, 200)
            self.assertIn(b"Dynamic Evidence", dynamic.data)
            self.assertIn(b"api.example.test", dynamic.data)
            self.assertIn(b"1 requests", dynamic.data)

            findings = client.get(f"/cases/{case_id}/findings")
            self.assertEqual(findings.status_code, 200)
            self.assertIn(b"Step-by-step validation chain", findings.data)
            self.assertIn(b"PoC / References", findings.data)
            self.assertIn(b"Open evidence", findings.data)
            self.assertIn(b"Tester Notes", findings.data)
            self.assertIn(b"Known vulnerability in com.squareup.okhttp3:okhttp", findings.data)
            self.assertIn(b"external vuln match", findings.data)
            self.assertIn(b"MASVS-CODE", findings.data)

            key_match = re.search(rb"/cases/[^/]+/findings/([a-f0-9]{16})/notes", findings.data)
            self.assertIsNotNone(key_match)
            finding_key = key_match.group(1).decode("ascii")
            save_finding_note = client.post(
                f"/cases/{case_id}/findings/{finding_key}/notes",
                data={
                    "status": "reviewed",
                    "notes": "confirmed in manifest",
                    "next": f"/cases/{case_id}/findings",
                },
            )
            self.assertEqual(save_finding_note.status_code, 302)
            findings = client.get(f"/cases/{case_id}/findings")
            self.assertIn(b"confirmed in manifest", findings.data)
            self.assertIn(b"reviewed", findings.data)

            report_page = client.get(f"/cases/{case_id}/report")
            self.assertEqual(report_page.status_code, 200)
            self.assertIn(b"Report Builder", report_page.data)
            self.assertIn(b"Export HTML", report_page.data)
            self.assertNotIn(b"Export PDF", report_page.data)

            case_dir = Path(app.config["STORAGE_DIR"]) / "cases" / case_id
            indicators_path = case_dir / "indicators.json"
            indicators_data = json.loads(indicators_path.read_text(encoding="utf-8"))
            indicators_data[0]["proof"] = "long-proof-" + ("A" * 3000)
            indicators_path.write_text(json.dumps(indicators_data), encoding="utf-8")

            report_export = client.post(
                f"/cases/{case_id}/report/export",
                data={
                    "format": "html",
                    "tester": "Unit Tester",
                    "notes": "authorized smoke test",
                    "include_indicators": "1",
                    "include_proxy": "1",
                },
            )
            self.assertEqual(report_export.status_code, 200)
            self.assertEqual(report_export.mimetype, "text/html")
            self.assertIn(".html", report_export.headers["Content-Disposition"])
            self.assertIn(b"APK Sentinel Case Report", report_export.data)
            self.assertIn(b"Step-by-step validation chain", report_export.data)
            self.assertIn(b"Proof Snippets", report_export.data)
            self.assertIn(b"confirmed in manifest", report_export.data)
            self.assertIn(b"table-layout: fixed", report_export.data)
            self.assertIn(b"overflow-wrap: anywhere", report_export.data)
            self.assertIn(b"evidence-card", report_export.data)
            self.assertIn(b"Vulnerability Intelligence", report_export.data)
            self.assertIn(b"CVE-2026-0001", report_export.data)

            archive_export = client.get(f"/cases/{case_id}/archive")
            self.assertEqual(archive_export.status_code, 200)
            self.assertEqual(archive_export.mimetype, "application/zip")
            with zipfile.ZipFile(io.BytesIO(archive_export.data)) as archive:
                names = set(archive.namelist())
                self.assertIn("archive.json", names)
                self.assertIn("case.json", names)
                self.assertIn("result.json", names)
                self.assertIn("files.json", names)
                self.assertIn("notes.json", names)
                self.assertIn("app.apk", names)

            archive_import = client.post(
                "/cases/archive/import",
                data={"archive": (io.BytesIO(archive_export.data), "case-export.zip")},
                content_type="multipart/form-data",
            )
            self.assertEqual(archive_import.status_code, 302)
            imported_overview = client.get(archive_import.headers["Location"])
            self.assertEqual(imported_overview.status_code, 200)
            self.assertIn(b"scope: authorized dashboard smoke", imported_overview.data)

            self.assertTrue(case_dir.exists())
            overview = client.get(location)
            self.assertIn(b"Delete Case", overview.data)
            delete = client.post(f"/cases/{case_id}/delete")
            self.assertEqual(delete.status_code, 302)
            self.assertFalse(case_dir.exists())
            self.assertEqual(client.get(location).status_code, 404)

    def test_proxy_lab_captures_replays_and_shows_response(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            storage = Path(temp_dir) / "store"
            app = create_app(storage_dir=storage)
            app.config.update(TESTING=True)
            client = app.test_client()

            proxy_port = _free_port()
            session = client.post(
                "/proxy/sessions",
                data={"label": "Standalone proxy smoke", "proxy_host": "127.0.0.1", "proxy_port": str(proxy_port)},
            )
            self.assertEqual(session.status_code, 302)
            lab_path = storage / "proxy_lab.json"
            session_id = json.loads(lab_path.read_text(encoding="utf-8"))["sessions"][0]["id"]

            origin_server, origin_thread = _start_origin_server()
            try:
                start = client.post("/proxy/start", data={"session_id": session_id})
                self.assertEqual(start.status_code, 302)

                connection = http.client.HTTPConnection("127.0.0.1", proxy_port, timeout=10)
                connection.request(
                    "GET",
                    f"http://127.0.0.1:{origin_server.server_address[1]}/ping?initial=1",
                    headers={"X-APK-Sentinel": "captured"},
                )
                proxied = connection.getresponse()
                self.assertEqual(proxied.status, 200)
                self.assertEqual(proxied.read(), b"pong")
                connection.close()

                stop = client.post("/proxy/stop", data={"session_id": session_id})
                self.assertEqual(stop.status_code, 302)

                repeater = client.get("/proxy/repeater", query_string={"capture_id": _first_capture_id(lab_path), "request_index": "0"})
                self.assertEqual(repeater.status_code, 200)
                self.assertIn(b"Repeater", repeater.data)
                self.assertIn(b"Raw Request", repeater.data)
                self.assertIn(b"GET http://127.0.0.1:", repeater.data)
                self.assertIn(b"Host: 127.0.0.1:", repeater.data)
                self.assertIn(b"X-APK-Sentinel: captured", repeater.data)
                self.assertIn(b"/ping?initial=1", repeater.data)

                raw_replay = (
                    f"POST /replay HTTP/1.1\r\n"
                    f"Host: 127.0.0.1:{origin_server.server_address[1]}\r\n"
                    "X-APK-Sentinel: replayed\r\n"
                    "Content-Type: text/plain\r\n"
                    "\r\n"
                    "manual-body"
                )
                replay = client.post(
                    "/proxy/repeater",
                    data={"raw_request": raw_replay},
                )
                self.assertEqual(replay.status_code, 200)
                self.assertIn(b"Response", replay.data)
                self.assertIn(b"echo:manual-body", replay.data)
            finally:
                origin_server.shutdown()
                origin_server.server_close()
                origin_thread.join(timeout=5)

            self.assertEqual(origin_server.records[0]["header"], "captured")
            self.assertEqual(origin_server.records[-1]["header"], "replayed")
            self.assertEqual(origin_server.records[-1]["body"], "manual-body")

            proxy_lab = client.get("/proxy")
            self.assertEqual(proxy_lab.status_code, 200)
            self.assertIn(b"Proxy Lab", proxy_lab.data)
            self.assertIn(b"built-in-proxy", proxy_lab.data)
            self.assertIn(b"1 requests", proxy_lab.data)
            self.assertIn(b"Send to Repeater", proxy_lab.data)

    @unittest.skipUnless(cryptography_available(), "cryptography unavailable")
    def test_proxy_lab_decrypts_https_after_ca_setup(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            storage = Path(temp_dir) / "store"
            ensure_ca(storage)
            app = create_app(storage_dir=storage)
            app.config.update(TESTING=True)
            client = app.test_client()

            proxy_port = _free_port()
            client.post(
                "/proxy/sessions",
                data={"label": "HTTPS MITM smoke", "proxy_host": "127.0.0.1", "proxy_port": str(proxy_port)},
            )
            lab_path = storage / "proxy_lab.json"
            session_id = json.loads(lab_path.read_text(encoding="utf-8"))["sessions"][0]["id"]
            origin_server, origin_thread = _start_tls_origin_server(storage)

            try:
                start = client.post("/proxy/start", data={"session_id": session_id})
                self.assertEqual(start.status_code, 302)

                target = f"127.0.0.1:{origin_server.server_address[1]}"
                context = ssl.create_default_context(cafile=str(ca_paths(storage)["cert"]))
                with socket.create_connection(("127.0.0.1", proxy_port), timeout=10) as sock:
                    sock.sendall(f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode("ascii"))
                    self.assertIn(b"200", sock.recv(4096))
                    with context.wrap_socket(sock, server_hostname="127.0.0.1") as tls_sock:
                        tls_sock.sendall(
                            (
                                f"GET /secure?x=1 HTTP/1.1\r\n"
                                f"Host: {target}\r\n"
                                "X-APK-Sentinel: tls\r\n"
                                "Connection: close\r\n"
                                "\r\n"
                            ).encode("ascii")
                        )
                        response = _recv_all(tls_sock)

                self.assertIn(b"200 OK", response)
                self.assertIn(b"secure-pong", response)
                stop = client.post("/proxy/stop", data={"session_id": session_id})
                self.assertEqual(stop.status_code, 302)
            finally:
                origin_server.shutdown()
                origin_server.server_close()
                origin_thread.join(timeout=5)

            self.assertEqual(origin_server.records[0]["header"], "tls")
            lab = json.loads(lab_path.read_text(encoding="utf-8"))
            captured = lab["captures"][0]["requests"]
            self.assertEqual([item["method"] for item in captured], ["GET"])
            self.assertEqual(captured[0]["scheme"], "https")
            self.assertTrue(captured[0]["tls_decrypted"])
            self.assertIn("/secure?x=1", captured[0]["url"])

    def test_proxy_lab_clears_history_and_deletes_sessions(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            storage = Path(temp_dir) / "store"
            app = create_app(storage_dir=storage)
            app.config.update(TESTING=True)
            client = app.test_client()

            client.post(
                "/proxy/sessions",
                data={"label": "Disposable proxy", "proxy_host": "127.0.0.1", "proxy_port": "8088"},
            )
            lab_path = storage / "proxy_lab.json"
            lab = json.loads(lab_path.read_text(encoding="utf-8"))
            session_id = lab["sessions"][0]["id"]
            proxy_dir = storage / "proxy_lab" / "proxy"
            proxy_dir.mkdir(parents=True, exist_ok=True)
            session_log = proxy_dir / f"{session_id}.jsonl"
            session_log.write_text('{"method":"GET","url":"http://example.test/"}\n', encoding="utf-8")
            lab["captures"] = [
                {
                    "id": "capture-1",
                    "session_id": session_id,
                    "source_name": "built-in-proxy.json",
                    "request_count": 1,
                    "domain_count": 1,
                    "cleartext_count": 1,
                    "top_domains": [["example.test", 1]],
                    "methods": {"GET": 1},
                    "statuses": {"200": 1},
                    "requests": [
                        {
                            "method": "GET",
                            "url": "http://example.test/",
                            "host": "example.test",
                            "path": "/",
                            "status": 200,
                            "request_bytes": 0,
                            "response_bytes": 4,
                        }
                    ],
                }
            ]
            lab["replays"] = [{"method": "GET", "url": "http://example.test/", "status": 200}]
            lab_path.write_text(json.dumps(lab), encoding="utf-8")

            proxy_lab = client.get("/proxy")
            self.assertEqual(proxy_lab.status_code, 200)
            self.assertIn(b"Clear History", proxy_lab.data)
            self.assertIn(b"Delete", proxy_lab.data)

            clear = client.post("/proxy/history/clear")
            self.assertEqual(clear.status_code, 302)
            lab = json.loads(lab_path.read_text(encoding="utf-8"))
            self.assertEqual(lab["captures"], [])
            self.assertEqual(lab["replays"], [])
            self.assertFalse(session_log.exists())

            client.post(
                "/proxy/sessions",
                data={"label": "Delete me", "proxy_host": "127.0.0.1", "proxy_port": "8089"},
            )
            lab = json.loads(lab_path.read_text(encoding="utf-8"))
            session_id = lab["sessions"][0]["id"]
            session_log = proxy_dir / f"{session_id}.jsonl"
            session_log.write_text('{"method":"POST","url":"http://example.test/"}\n', encoding="utf-8")
            lab["captures"] = [{"id": "capture-2", "session_id": session_id, "request_count": 1, "requests": []}]
            lab_path.write_text(json.dumps(lab), encoding="utf-8")

            delete = client.post(f"/proxy/sessions/{session_id}/delete")
            self.assertEqual(delete.status_code, 302)
            lab = json.loads(lab_path.read_text(encoding="utf-8"))
            self.assertFalse(any(item["id"] == session_id for item in lab["sessions"]))
            self.assertEqual(lab["captures"], [])
            self.assertFalse(session_log.exists())

    @unittest.skipUnless(cryptography_available(), "cryptography unavailable")
    def test_proxy_lab_generates_and_downloads_ca(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            storage = Path(temp_dir) / "store"
            app = create_app(storage_dir=storage)
            app.config.update(TESTING=True)
            client = app.test_client()

            proxy_lab = client.get("/proxy")
            self.assertEqual(proxy_lab.status_code, 200)
            self.assertIn(b"TLS CA", proxy_lab.data)
            self.assertIn(b"Generate CA", proxy_lab.data)

            create = client.post("/proxy/ca")
            self.assertEqual(create.status_code, 302)

            proxy_lab = client.get("/proxy")
            self.assertEqual(proxy_lab.status_code, 200)
            self.assertIn(b"Browser / Brave", proxy_lab.data)
            self.assertIn(b"Android User CA", proxy_lab.data)
            self.assertIn(b"Android System CA", proxy_lab.data)
            self.assertIn(b"SHA-256 Fingerprint", proxy_lab.data)
            self.assertIn(b"Android System Name", proxy_lab.data)
            self.assertIn(b"Ready", proxy_lab.data)

            download = client.get("/proxy/ca/download")
            self.assertEqual(download.status_code, 200)
            self.assertIn(b"BEGIN CERTIFICATE", download.data)
            self.assertIn("apk-sentinel-ca.pem", download.headers["Content-Disposition"])

            browser = client.get("/proxy/ca/download/browser-cer")
            self.assertEqual(browser.status_code, 200)
            self.assertTrue(browser.data.startswith(b"0"))
            self.assertIn("apk-sentinel-browser-ca.cer", browser.headers["Content-Disposition"])

            android_user = client.get("/proxy/ca/download/android-user")
            self.assertEqual(android_user.status_code, 200)
            self.assertTrue(android_user.data.startswith(b"0"))
            self.assertIn("apk-sentinel-android-user-ca.crt", android_user.headers["Content-Disposition"])

            android_system = client.get("/proxy/ca/download/android-system")
            self.assertEqual(android_system.status_code, 200)
            self.assertIn(b"BEGIN CERTIFICATE", android_system.data)
            self.assertRegex(android_system.headers["Content-Disposition"], r"filename=[a-f0-9]{8}\.0")

    def test_proxy_lab_intercepts_until_forwarded(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            storage = Path(temp_dir) / "store"
            app = create_app(storage_dir=storage)
            app.config.update(TESTING=True)
            client = app.test_client()

            proxy_port = _free_port()
            client.post(
                "/proxy/sessions",
                data={"label": "Intercept smoke", "proxy_host": "127.0.0.1", "proxy_port": str(proxy_port)},
            )
            client.post("/proxy/intercept/on")
            lab_path = storage / "proxy_lab.json"
            session_id = json.loads(lab_path.read_text(encoding="utf-8"))["sessions"][0]["id"]

            origin_server, origin_thread = _start_origin_server()
            result: dict = {}
            pending: dict | None = None

            def send_through_proxy() -> None:
                connection = http.client.HTTPConnection("127.0.0.1", proxy_port, timeout=10)
                connection.request(
                    "GET",
                    f"http://127.0.0.1:{origin_server.server_address[1]}/hold?x=1",
                    headers={"X-APK-Sentinel": "captured"},
                )
                response = connection.getresponse()
                result["status"] = response.status
                result["body"] = response.read()
                connection.close()

            requester = threading.Thread(target=send_through_proxy, daemon=True)
            try:
                start = client.post("/proxy/start", data={"session_id": session_id})
                self.assertEqual(start.status_code, 302)

                requester.start()
                pending = _wait_for_pending(app)
                self.assertEqual(len(origin_server.records), 0)

                proxy_lab = client.get("/proxy")
                self.assertEqual(proxy_lab.status_code, 200)
                self.assertIn(b"Interceptor", proxy_lab.data)
                self.assertIn(b"paused", proxy_lab.data)
                self.assertIn(b"/hold", proxy_lab.data)

                raw_request = pending["raw_request_text"]
                raw_request = raw_request.replace("/hold?x=1", "/forwarded?x=2")
                raw_request = raw_request.replace("X-APK-Sentinel: captured", "X-APK-Sentinel: forwarded")
                forward = client.post(f"/proxy/intercept/{pending['id']}/forward", data={"raw_request": raw_request})
                self.assertEqual(forward.status_code, 302)
                requester.join(timeout=5)
                self.assertFalse(requester.is_alive())
                self.assertEqual(result["status"], 200)
                self.assertEqual(result["body"], b"pong")

                live_history = client.get("/proxy/repeater")
                self.assertEqual(live_history.status_code, 200)
                self.assertIn(b"Request History", live_history.data)
                self.assertIn(b"(live)", live_history.data)
                self.assertIn(b"/forwarded?x=2", live_history.data)
                self.assertIn(b"GET", live_history.data)

                live_repeater = client.get(
                    "/proxy/repeater",
                    query_string={"capture_id": f"live-{session_id}", "request_index": "0"},
                )
                self.assertEqual(live_repeater.status_code, 200)
                self.assertIn(b"Raw Request", live_repeater.data)
                self.assertIn(b"X-APK-Sentinel: forwarded", live_repeater.data)

                stop = client.post("/proxy/stop", data={"session_id": session_id})
                self.assertEqual(stop.status_code, 302)
            finally:
                if requester.is_alive() and pending:
                    app.config["PROXY_MANAGER"].resolve_intercept("proxy-lab", pending["id"], "drop")
                    requester.join(timeout=5)
                origin_server.shutdown()
                origin_server.server_close()
                origin_thread.join(timeout=5)

            self.assertEqual(origin_server.records[0]["header"], "forwarded")
            self.assertIn("/forwarded?x=2", origin_server.records[0]["path"])

            lab = json.loads(lab_path.read_text(encoding="utf-8"))
            captured = lab["captures"][0]["requests"][0]
            self.assertTrue(captured["paused_by_interceptor"])
            self.assertEqual(captured["intercept_action"], "forwarded")
            self.assertIn("/forwarded?x=2", captured["raw_request_text"])

    def test_proxy_lab_intercepts_connect_tunnels_until_forwarded(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            storage = Path(temp_dir) / "store"
            app = create_app(storage_dir=storage)
            app.config.update(TESTING=True)
            client = app.test_client()

            proxy_port = _free_port()
            client.post(
                "/proxy/sessions",
                data={"label": "CONNECT smoke", "proxy_host": "127.0.0.1", "proxy_port": str(proxy_port)},
            )
            client.post("/proxy/intercept/on")
            lab_path = storage / "proxy_lab.json"
            session_id = json.loads(lab_path.read_text(encoding="utf-8"))["sessions"][0]["id"]

            origin_server, origin_thread = _start_origin_server()
            result: dict = {}
            pending: dict | None = None

            def connect_through_proxy() -> None:
                with socket.create_connection(("127.0.0.1", proxy_port), timeout=10) as sock:
                    target = f"127.0.0.1:{origin_server.server_address[1]}"
                    sock.sendall(f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode("ascii"))
                    result["response"] = sock.recv(4096)

            requester = threading.Thread(target=connect_through_proxy, daemon=True)
            try:
                start = client.post("/proxy/start", data={"session_id": session_id})
                self.assertEqual(start.status_code, 302)

                requester.start()
                pending = _wait_for_pending(app)
                self.assertEqual(pending["method"], "CONNECT")
                self.assertIn("CONNECT 127.0.0.1:", pending["raw_request_text"])
                self.assertTrue(requester.is_alive())

                forward = client.post(
                    f"/proxy/intercept/{pending['id']}/forward",
                    data={"raw_request": pending["raw_request_text"]},
                )
                self.assertEqual(forward.status_code, 302)
                requester.join(timeout=5)
                self.assertFalse(requester.is_alive())
                self.assertIn(b"200", result["response"])

                stop = client.post("/proxy/stop", data={"session_id": session_id})
                self.assertEqual(stop.status_code, 302)
            finally:
                if requester.is_alive() and pending:
                    app.config["PROXY_MANAGER"].resolve_intercept("proxy-lab", pending["id"], "drop")
                    requester.join(timeout=5)
                origin_server.shutdown()
                origin_server.server_close()
                origin_thread.join(timeout=5)

            lab = json.loads(lab_path.read_text(encoding="utf-8"))
            captured = lab["captures"][0]["requests"][0]
            self.assertEqual(captured["method"], "CONNECT")
            self.assertTrue(captured["paused_by_interceptor"])
            self.assertEqual(captured["intercept_action"], "forwarded")

    def test_proxy_lab_forward_all_pending_intercepts(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            storage = Path(temp_dir) / "store"
            app = create_app(storage_dir=storage)
            app.config.update(TESTING=True)
            client = app.test_client()

            proxy_port = _free_port()
            client.post(
                "/proxy/sessions",
                data={"label": "Forward all smoke", "proxy_host": "127.0.0.1", "proxy_port": str(proxy_port)},
            )
            client.post("/proxy/intercept/on")
            lab_path = storage / "proxy_lab.json"
            session_id = json.loads(lab_path.read_text(encoding="utf-8"))["sessions"][0]["id"]

            origin_server, origin_thread = _start_origin_server()
            results: list[int] = []
            requesters: list[threading.Thread] = []

            def send_path(path: str) -> None:
                connection = http.client.HTTPConnection("127.0.0.1", proxy_port, timeout=10)
                connection.request("GET", f"http://127.0.0.1:{origin_server.server_address[1]}{path}")
                response = connection.getresponse()
                results.append(response.status)
                response.read()
                connection.close()

            try:
                start = client.post("/proxy/start", data={"session_id": session_id})
                self.assertEqual(start.status_code, 302)

                for path in ("/one", "/two"):
                    thread = threading.Thread(target=send_path, args=(path,), daemon=True)
                    requesters.append(thread)
                    thread.start()

                pending = _wait_for_pending_count(app, 2)
                self.assertEqual(len(origin_server.records), 0)

                proxy_lab = client.get("/proxy")
                self.assertIn(b"Turn Intercept Off", proxy_lab.data)
                self.assertIn(b"Forward All", proxy_lab.data)
                self.assertNotIn(b"Apply", proxy_lab.data)

                forward_all = client.post("/proxy/intercept/forward-all")
                self.assertEqual(forward_all.status_code, 302)
                for thread in requesters:
                    thread.join(timeout=5)
                    self.assertFalse(thread.is_alive())

                stop = client.post("/proxy/stop", data={"session_id": session_id})
                self.assertEqual(stop.status_code, 302)
            finally:
                for item in app.config["PROXY_MANAGER"].pending_intercepts("proxy-lab"):
                    app.config["PROXY_MANAGER"].resolve_intercept("proxy-lab", item["id"], "drop")
                for thread in requesters:
                    thread.join(timeout=5)
                origin_server.shutdown()
                origin_server.server_close()
                origin_thread.join(timeout=5)

            self.assertEqual(sorted(results), [200, 200])
            self.assertEqual(len(origin_server.records), 2)
            lab = json.loads(lab_path.read_text(encoding="utf-8"))
            captured = lab["captures"][0]["requests"]
            self.assertEqual(len(captured), 2)
            self.assertTrue(all(item["intercept_action"] == "forwarded" for item in captured))


def _apk_bytes() -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("AndroidManifest.xml", DASHBOARD_MANIFEST)
        archive.writestr("classes.dex", b"dex\n035\0")
        archive.writestr(
            "META-INF/maven/com.squareup.okhttp3/okhttp/pom.properties",
            b"groupId=com.squareup.okhttp3\nartifactId=okhttp\nversion=4.9.0\n",
        )
        archive.writestr(
            "assets/config.json",
            b'{"env":"test","key":"AIzaAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","endpoint":"http://api.example.test/v1"}',
        )
    buffer.seek(0)
    return buffer.read()


def _write_test_vuln_db(storage: Path) -> None:
    cache_key = "Maven|com.squareup.okhttp3:okhttp|4.9.0|pkg:maven/com/squareup/okhttp3/okhttp@4.9.0"
    data = {
        "schema": 1,
        "updated_at": "2026-06-30T00:00:00+00:00",
        "sources": {"osv": {"status": "ok", "updated_at": "2026-06-30T00:00:00+00:00", "error": ""}},
        "packages": {
            cache_key: {
                "source": "OSV",
                "ecosystem": "Maven",
                "name": "com.squareup.okhttp3:okhttp",
                "version": "4.9.0",
                "purl": "pkg:maven/com/squareup/okhttp3/okhttp@4.9.0",
                "queried_at": "2026-06-30T00:00:00+00:00",
                "vulnerabilities": [
                    {
                        "id": "CVE-2026-0001",
                        "aliases": ["CVE-2026-0001"],
                        "summary": "Test advisory for vulnerable OkHttp package",
                        "details": "Reachability must be validated before reporting exploitability.",
                        "severity": "high",
                        "published": "2026-01-01T00:00:00Z",
                        "modified": "2026-01-02T00:00:00Z",
                        "references": [{"type": "ADVISORY", "url": "https://osv.dev/vulnerability/CVE-2026-0001"}],
                    }
                ],
            }
        },
    }
    (storage / "vuln_db.json").write_text(json.dumps(data), encoding="utf-8")


def _har_bytes() -> bytes:
    return b"""{
  "log": {
    "version": "1.2",
    "creator": {"name": "APK Sentinel test", "version": "1"},
    "entries": [
      {
        "startedDateTime": "2026-06-28T19:00:00Z",
        "request": {
          "method": "GET",
          "url": "https://api.example.test/v1/profile"
        },
        "response": {
          "status": 200,
          "content": {"mimeType": "application/json"}
        }
      }
    ]
  }
}"""


class _OriginHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        self.server.records.append(
            {
                "path": self.path,
                "header": self.headers.get("X-APK-Sentinel"),
                "body": "",
            }
        )
        body = b"secure-pong" if self.path.startswith("/secure") else b"pong"
        self.send_response(200)
        self.send_header("content-type", "text/plain")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:
        length = int(self.headers.get("content-length", "0"))
        body = self.rfile.read(length).decode("utf-8", errors="replace") if length else ""
        self.server.records.append(
            {
                "path": self.path,
                "header": self.headers.get("X-APK-Sentinel"),
                "body": body,
            }
        )
        response = f"echo:{body}".encode("utf-8")
        self.send_response(200)
        self.send_header("content-type", "text/plain")
        self.send_header("content-length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)

    def log_message(self, _format: str, *_args) -> None:
        return


def _start_origin_server() -> tuple[ThreadingHTTPServer, threading.Thread]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _OriginHandler)
    server.records = []
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def _start_tls_origin_server(storage: Path) -> tuple[ThreadingHTTPServer, threading.Thread]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _OriginHandler)
    certs = ensure_host_certificate(storage, storage / "origin-certs", "127.0.0.1")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certs["cert"], certs["key"])
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.records = []
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def _recv_all(sock: ssl.SSLSocket) -> bytes:
    data = b""
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            return data
        data += chunk


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _first_capture_id(lab_path: Path) -> str:
    return json.loads(lab_path.read_text(encoding="utf-8"))["captures"][0]["id"]


def _wait_for_pending(app) -> dict:
    deadline = time.time() + 5
    while time.time() < deadline:
        pending = app.config["PROXY_MANAGER"].pending_intercepts("proxy-lab")
        if pending:
            return pending[0]
        time.sleep(0.05)
    raise AssertionError("Timed out waiting for intercepted request")


def _wait_for_pending_count(app, count: int) -> list[dict]:
    deadline = time.time() + 5
    while time.time() < deadline:
        pending = app.config["PROXY_MANAGER"].pending_intercepts("proxy-lab")
        if len(pending) >= count:
            return pending
        time.sleep(0.05)
    raise AssertionError(f"Timed out waiting for {count} intercepted requests")


if __name__ == "__main__":
    unittest.main()
