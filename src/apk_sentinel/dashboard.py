from __future__ import annotations

import json
import os
import re
import shutil
import zipfile
from collections import Counter
from dataclasses import asdict
from datetime import datetime, timezone
from hashlib import sha1
from html import escape as html_escape
from io import BytesIO
from pathlib import Path, PurePosixPath
import xml.etree.ElementTree as ET

from flask import Flask, abort, flash, redirect, render_template, request, send_file, url_for
from werkzeug.utils import secure_filename

from apk_sentinel import __version__
from apk_sentinel.axml import AxmlParseError, parse_xml_bytes
from apk_sentinel.capture_proxy import CaptureProxyManager
from apk_sentinel.core import scan_apk
from apk_sentinel.dynamic import create_session as make_dynamic_session
from apk_sentinel.dynamic import empty_dynamic_state, import_capture
from apk_sentinel.finding_guidance import enrich_finding_dict
from apk_sentinel.indicators import extract_indicators
from apk_sentinel.inventory import extract_dependency_inventory
from apk_sentinel.models import SEVERITY_ORDER
from apk_sentinel.replay import blank_replay_draft, draft_from_request, replay_raw_http_request
from apk_sentinel.report_template import BASE_CSS as REPORT_BASE_CSS
from apk_sentinel.report_template import REPORT_TOOLBAR_HTML, finding_card_html
from apk_sentinel.tls_ca import ca_status, ensure_ca, export_ca
from apk_sentinel.vuln_intel import load_vuln_db, match_vulnerabilities, update_osv_cache, vuln_match_to_finding

PREVIEW_BYTES = 256 * 1024
XML_PREVIEW_BYTES = 2 * 1024 * 1024
HEX_PREVIEW_BYTES = 4096
STRING_PREVIEW_BYTES = 512 * 1024
STRING_SEARCH_BYTES = 384 * 1024
MAX_STRING_LINES = 1200
MAX_DEEP_SEARCH_HITS = 80
CASE_ARCHIVE_VERSION = 1

DEFAULT_SETTINGS = {
    "report_author": "",
    "default_proxy_host": "127.0.0.1",
    "default_proxy_port": 8088,
}

FINDING_STATUSES = ["open", "reviewed", "accepted risk", "false positive"]

TEXT_EXTENSIONS = {
    ".cfg",
    ".conf",
    ".config",
    ".csv",
    ".ini",
    ".json",
    ".pem",
    ".properties",
    ".pro",
    ".txt",
    ".xml",
    ".yaml",
    ".yml",
}


def create_app(storage_dir: str | Path | None = None) -> Flask:
    app = Flask(__name__)
    app.secret_key = os.environ.get("APK_SENTINEL_SECRET", "apk-sentinel-local-dev")
    app.config["MAX_CONTENT_LENGTH"] = int(os.environ.get("APK_SENTINEL_MAX_UPLOAD_MB", "1024")) * 1024 * 1024
    app.config["PROJECT_DIR"] = Path.cwd().resolve()
    app.config["STORAGE_DIR"] = _storage_path(storage_dir)
    app.config["PROXY_MANAGER"] = CaptureProxyManager()
    _ensure_storage(app.config["STORAGE_DIR"])

    @app.context_processor
    def inject_globals():
        return {"app_version": __version__}

    @app.template_filter("filesize")
    def filesize_filter(size: int | None) -> str:
        return _format_bytes(size or 0)

    @app.template_filter("countseverity")
    def count_severity(findings: list[dict], severity: str) -> int:
        return sum(1 for finding in findings if finding.get("severity") == severity)

    @app.errorhandler(404)
    def not_found(error):
        return render_template("dashboard/error.html", active="", code=404, title="Not Found", message="That page, case, or artifact could not be found."), 404

    @app.errorhandler(413)
    def too_large(error):
        return render_template("dashboard/error.html", active="", code=413, title="Upload Too Large", message="The uploaded file is larger than this dashboard accepts."), 413

    @app.errorhandler(500)
    def server_error(error):
        return render_template("dashboard/error.html", active="", code=500, title="Dashboard Error", message="Something failed while handling the request. Check the terminal or dashboard log for details."), 500

    @app.get("/")
    def index():
        cases = _list_cases(app.config["STORAGE_DIR"])
        local_apks = _local_apks(app.config["PROJECT_DIR"], app.config["STORAGE_DIR"])
        settings = _load_settings(app.config["STORAGE_DIR"])
        return render_template(
            "dashboard/index.html",
            active="dashboard",
            cases=cases,
            local_apks=local_apks,
            settings=settings,
        )

    @app.route("/settings", methods=["GET", "POST"])
    def settings():
        storage_dir = app.config["STORAGE_DIR"]
        current = _load_settings(storage_dir)
        if request.method == "POST":
            current["report_author"] = request.form.get("report_author", "").strip()
            current["default_proxy_host"] = request.form.get("default_proxy_host", "127.0.0.1").strip() or "127.0.0.1"
            try:
                port = int(request.form.get("default_proxy_port", "8088"))
            except ValueError:
                port = 8088
            current["default_proxy_port"] = max(1, min(port, 65535))
            _write_settings(storage_dir, current)
            flash("Settings saved.", "info")
            return redirect(url_for("settings"))
        return render_template(
            "dashboard/settings.html",
            active="settings",
            settings=current,
            storage_dir=storage_dir,
            project_dir=app.config["PROJECT_DIR"],
            max_upload_mb=app.config["MAX_CONTENT_LENGTH"] // (1024 * 1024),
        )

    @app.get("/about")
    def about():
        return render_template(
            "dashboard/about.html",
            active="about",
            version=__version__,
            storage_dir=app.config["STORAGE_DIR"],
            project_dir=app.config["PROJECT_DIR"],
        )

    @app.get("/intelligence")
    def vulnerability_intelligence():
        storage_dir = app.config["STORAGE_DIR"]
        db = load_vuln_db(storage_dir)
        cases = _list_cases(storage_dir)
        dependencies = _all_case_dependencies(storage_dir)
        package_count = len(db.get("packages", {}))
        vuln_count = sum(len(item.get("vulnerabilities", [])) for item in db.get("packages", {}).values())
        return render_template(
            "dashboard/intelligence.html",
            active="intelligence",
            db=db,
            cases=cases,
            dependencies=dependencies,
            package_count=package_count,
            vuln_count=vuln_count,
        )

    @app.post("/intelligence/update")
    def update_vulnerability_intelligence():
        storage_dir = app.config["STORAGE_DIR"]
        dependencies = _all_case_dependencies(storage_dir)
        result = update_osv_cache(storage_dir, dependencies)
        if result.get("error"):
            flash(f"OSV update failed: {result['error']}", "error")
        else:
            flash(f"OSV update complete: {result['queried']} package(s), {result['vulnerabilities']} vulnerability match(es).", "info")
        return redirect(url_for("vulnerability_intelligence"))

    @app.get("/proxy")
    def proxy_lab():
        lab = _load_proxy_lab(app.config["STORAGE_DIR"])
        _attach_proxy_lab_status(lab, app.config["PROXY_MANAGER"])
        lab["ca"] = ca_status(app.config["STORAGE_DIR"])
        lab["settings"] = _load_settings(app.config["STORAGE_DIR"])
        return render_template("dashboard/proxy.html", active="proxy", lab=lab)

    @app.post("/proxy/ca")
    def create_proxy_ca():
        try:
            ensure_ca(app.config["STORAGE_DIR"])
            flash("Local testing CA is ready. Install it only on browsers/devices in your authorized test scope.", "info")
        except RuntimeError as exc:
            flash(str(exc), "error")
        return redirect(url_for("proxy_lab"))

    @app.get("/proxy/ca/download", defaults={"profile": "pem"})
    @app.get("/proxy/ca/download/<profile>")
    def download_proxy_ca(profile: str):
        status = ca_status(app.config["STORAGE_DIR"])
        if not status["exists"]:
            flash("Generate the local CA first.", "error")
            return redirect(url_for("proxy_lab"))

        try:
            export = export_ca(app.config["STORAGE_DIR"], profile)
        except (RuntimeError, ValueError, FileNotFoundError) as exc:
            flash(str(exc), "error")
            return redirect(url_for("proxy_lab"))

        return send_file(
            BytesIO(export["data"]),
            download_name=export["download_name"],
            mimetype=export["mimetype"],
            as_attachment=True,
        )

    @app.route("/proxy/repeater", methods=["GET", "POST"])
    def proxy_repeater():
        lab = _load_proxy_lab(app.config["STORAGE_DIR"])
        _attach_proxy_lab_status(lab, app.config["PROXY_MANAGER"])
        selected_request = _find_lab_request(
            lab,
            request.values.get("capture_id", ""),
            request.values.get("request_index", ""),
        )
        replay = None

        if request.method == "POST":
            draft = {"raw_request": request.form.get("raw_request", "")}
            replay = replay_raw_http_request(draft["raw_request"])
            lab["replays"].insert(0, replay)
            lab["replays"] = lab["replays"][:100]
            _write_proxy_lab(app.config["STORAGE_DIR"], lab)
        else:
            if request.args.get("capture_id") and selected_request is None:
                flash("That captured request could not be found.", "error")
            draft = draft_from_request(selected_request) if selected_request else blank_replay_draft()

        return render_template(
            "dashboard/repeater.html",
            active="repeater",
            lab=lab,
            draft=draft,
            replay=replay,
            selected_request=selected_request,
        )

    @app.post("/proxy/history/clear")
    def clear_proxy_history():
        storage_dir = app.config["STORAGE_DIR"]
        lab = _load_proxy_lab(storage_dir)
        saved_request_count = sum(capture.get("request_count", 0) for capture in lab.get("captures", []))
        replay_count = len(lab.get("replays", []))
        live_request_count = app.config["PROXY_MANAGER"].clear_history("proxy-lab")
        lab["captures"] = []
        lab["replays"] = []
        _clear_proxy_history_files(storage_dir)
        _write_proxy_lab(storage_dir, lab)
        flash(f"Cleared {saved_request_count + live_request_count} request(s) and {replay_count} replay(s).", "info")
        return redirect(url_for("proxy_lab"))

    @app.post("/proxy/intercept/<state>")
    def set_proxy_intercept(state: str):
        lab = _load_proxy_lab(app.config["STORAGE_DIR"])
        enabled = state == "on"
        lab["intercept_enabled"] = enabled
        app.config["PROXY_MANAGER"].set_intercept_enabled("proxy-lab", enabled)
        _write_proxy_lab(app.config["STORAGE_DIR"], lab)
        flash(f"Intercept is {'on' if enabled else 'off'}.", "info")
        return redirect(url_for("proxy_lab"))

    @app.post("/proxy/intercept/forward-all")
    def forward_all_proxy_intercepts():
        count = app.config["PROXY_MANAGER"].forward_all_intercepts("proxy-lab")
        flash(f"Forwarded {count} intercepted request(s).", "info")
        return redirect(url_for("proxy_lab"))

    @app.post("/proxy/intercept/<request_id>/forward")
    def forward_proxy_intercept(request_id: str):
        raw_request = request.form.get("raw_request", "")
        if app.config["PROXY_MANAGER"].resolve_intercept("proxy-lab", request_id, "forward", raw_request):
            flash("Intercepted request forwarded.", "info")
        else:
            flash("That intercepted request is no longer pending.", "error")
        return redirect(url_for("proxy_lab"))

    @app.post("/proxy/intercept/<request_id>/drop")
    def drop_proxy_intercept(request_id: str):
        if app.config["PROXY_MANAGER"].resolve_intercept("proxy-lab", request_id, "drop"):
            flash("Intercepted request dropped.", "info")
        else:
            flash("That intercepted request is no longer pending.", "error")
        return redirect(url_for("proxy_lab"))

    @app.post("/proxy/sessions")
    def create_proxy_session():
        lab = _load_proxy_lab(app.config["STORAGE_DIR"])
        settings = _load_settings(app.config["STORAGE_DIR"])
        label = request.form.get("label", "").strip()
        host = request.form.get("proxy_host", settings["default_proxy_host"]).strip() or settings["default_proxy_host"]
        try:
            port = int(request.form.get("proxy_port", str(settings["default_proxy_port"])))
        except ValueError:
            port = int(settings["default_proxy_port"])
        notes = request.form.get("notes", "").strip()
        lab["sessions"].insert(0, make_dynamic_session(label, host, port, notes))
        _write_proxy_lab(app.config["STORAGE_DIR"], lab)
        return redirect(url_for("proxy_lab"))

    @app.post("/proxy/sessions/<session_id>/delete")
    def delete_proxy_session(session_id: str):
        storage_dir = app.config["STORAGE_DIR"]
        lab = _load_proxy_lab(storage_dir)
        session = _find_lab_session(lab, session_id)
        if not session:
            flash("That proxy session could not be found.", "error")
            return redirect(url_for("proxy_lab"))

        app.config["PROXY_MANAGER"].stop("proxy-lab", session_id)
        app.config["PROXY_MANAGER"].clear_history("proxy-lab", session_id)
        lab["sessions"] = [item for item in lab["sessions"] if item.get("id") != session_id]
        lab["captures"] = [capture for capture in lab.get("captures", []) if capture.get("session_id") != session_id]
        _delete_proxy_session_file(storage_dir, session_id)
        _write_proxy_lab(storage_dir, lab)
        flash(f"Deleted proxy session {session.get('label') or session_id}.", "info")
        return redirect(url_for("proxy_lab"))

    @app.post("/proxy/rules")
    def create_proxy_rule():
        lab = _load_proxy_lab(app.config["STORAGE_DIR"])
        action = request.form.get("action", "set_header")
        name = request.form.get("name", "").strip() or action.replace("_", " ").title()
        rule = {
            "id": f"{_timestamp()}-{_slug(name)}",
            "enabled": True,
            "name": name,
            "action": action,
            "match_method": request.form.get("match_method", "ANY").strip().upper() or "ANY",
            "match_host": request.form.get("match_host", "").strip(),
            "match_path": request.form.get("match_path", "").strip(),
            "header_name": request.form.get("header_name", "").strip(),
            "header_value": request.form.get("header_value", ""),
            "query_name": request.form.get("query_name", "").strip(),
            "query_value": request.form.get("query_value", ""),
            "block_status": request.form.get("block_status", "403").strip(),
            "block_body": request.form.get("block_body", "").strip(),
        }
        lab["rules"].insert(0, rule)
        _write_proxy_lab(app.config["STORAGE_DIR"], lab)
        return redirect(url_for("proxy_lab"))

    @app.post("/proxy/rules/<rule_id>/delete")
    def delete_proxy_rule(rule_id: str):
        lab = _load_proxy_lab(app.config["STORAGE_DIR"])
        lab["rules"] = [rule for rule in lab["rules"] if rule.get("id") != rule_id]
        _write_proxy_lab(app.config["STORAGE_DIR"], lab)
        return redirect(url_for("proxy_lab"))

    @app.post("/proxy/start")
    def start_proxy_lab_session():
        lab = _load_proxy_lab(app.config["STORAGE_DIR"])
        session_id = request.form.get("session_id", "")
        session = _find_lab_session(lab, session_id)
        if not session:
            flash("Choose a valid proxy session first.", "error")
            return redirect(url_for("proxy_lab"))

        try:
            port = int(session.get("proxy_port", 8088))
        except (TypeError, ValueError):
            port = 8088
        host = session.get("proxy_host") or "127.0.0.1"
        rules: list[dict] = []

        try:
            instance = app.config["PROXY_MANAGER"].start(
                "proxy-lab",
                session_id,
                host,
                port,
                app.config["STORAGE_DIR"] / "proxy_lab",
                rules,
                bool(lab.get("intercept_enabled", False)),
                app.config["STORAGE_DIR"],
            )
        except OSError as exc:
            flash(f"Proxy could not start on {host}:{port}: {exc}", "error")
            return redirect(url_for("proxy_lab"))

        session["status"] = "running"
        session["proxy_host"] = instance.host
        session["proxy_port"] = instance.port
        session["proxy_started_at"] = instance.started_at
        session["rule_count"] = 0
        _write_proxy_lab(app.config["STORAGE_DIR"], lab)
        flash(f"Proxy Lab listening on {instance.host}:{instance.port}.", "info")
        return redirect(url_for("proxy_lab"))

    @app.post("/proxy/stop")
    def stop_proxy_lab_session():
        lab = _load_proxy_lab(app.config["STORAGE_DIR"])
        session_id = request.form.get("session_id", "")
        session = _find_lab_session(lab, session_id)
        if not session:
            flash("Choose a valid proxy session first.", "error")
            return redirect(url_for("proxy_lab"))

        capture = app.config["PROXY_MANAGER"].stop("proxy-lab", session_id)
        if capture is None:
            flash("That proxy session is not running in this dashboard process.", "error")
            session["status"] = "planned"
            _write_proxy_lab(app.config["STORAGE_DIR"], lab)
            return redirect(url_for("proxy_lab"))

        session["status"] = "stopped"
        session["proxy_stopped_at"] = datetime.now(timezone.utc).isoformat()
        if capture["request_count"]:
            lab["captures"].insert(0, capture)
            flash(f"Proxy stopped and saved {capture['request_count']} captured request(s).", "info")
        else:
            flash("Proxy stopped. No requests were captured.", "info")
        _write_proxy_lab(app.config["STORAGE_DIR"], lab)
        return redirect(url_for("proxy_lab"))

    @app.post("/cases")
    def create_case():
        upload = request.files.get("apk")
        if not upload or not upload.filename:
            flash("Choose an APK file first.", "error")
            return redirect(url_for("index"))

        safe_name = secure_filename(upload.filename) or "uploaded.apk"
        if not safe_name.lower().endswith(".apk"):
            flash("Only APK files are accepted for this dashboard.", "error")
            return redirect(url_for("index"))

        incoming_dir = app.config["STORAGE_DIR"] / "incoming"
        incoming_dir.mkdir(parents=True, exist_ok=True)
        incoming_path = incoming_dir / f"{_timestamp()}-{safe_name}"
        upload.save(incoming_path)

        try:
            case_id = _create_case_from_path(incoming_path, app.config["STORAGE_DIR"], safe_name)
        except Exception as exc:  # pragma: no cover - Flask renders the message for humans.
            flash(f"APK import failed: {exc}", "error")
            return redirect(url_for("index"))
        finally:
            if incoming_path.exists():
                incoming_path.unlink()

        return redirect(url_for("case_overview", case_id=case_id))

    @app.post("/cases/import")
    def import_case():
        requested = request.form.get("apk_path", "")
        source = Path(requested).resolve()
        allowed = {item["path"] for item in _local_apks(app.config["PROJECT_DIR"], app.config["STORAGE_DIR"])}
        if str(source) not in allowed:
            flash("That APK is not available for local import.", "error")
            return redirect(url_for("index"))

        try:
            case_id = _create_case_from_path(source, app.config["STORAGE_DIR"], source.name)
        except Exception as exc:  # pragma: no cover - Flask renders the message for humans.
            flash(f"APK import failed: {exc}", "error")
            return redirect(url_for("index"))

        return redirect(url_for("case_overview", case_id=case_id))

    @app.post("/cases/archive/import")
    def import_case_archive():
        upload = request.files.get("archive")
        if not upload or not upload.filename:
            flash("Choose a case archive ZIP first.", "error")
            return redirect(url_for("index"))
        safe_name = secure_filename(upload.filename) or "case.zip"
        if not safe_name.lower().endswith(".zip"):
            flash("Case archives must be ZIP files exported by APK Sentinel.", "error")
            return redirect(url_for("index"))
        try:
            case_id = _import_case_archive(upload.stream, app.config["STORAGE_DIR"], safe_name)
        except (ValueError, zipfile.BadZipFile, OSError, KeyError) as exc:
            flash(f"Case archive import failed: {exc}", "error")
            return redirect(url_for("index"))
        flash(f"Imported case archive {safe_name}.", "info")
        return redirect(url_for("case_overview", case_id=case_id))

    @app.get("/cases/<case_id>")
    def case_overview(case_id: str):
        case = _load_case(app.config["STORAGE_DIR"], case_id)
        return render_template("dashboard/overview.html", active="overview", case=case)

    @app.post("/cases/<case_id>/notes")
    def save_case_notes(case_id: str):
        case = _load_case(app.config["STORAGE_DIR"], case_id)
        notes = _load_case_notes(Path(case["dir"]))
        notes["case_notes"] = request.form.get("case_notes", "").strip()
        notes["updated_at"] = datetime.now(timezone.utc).isoformat()
        _write_case_notes(Path(case["dir"]), notes)
        flash("Case notes saved.", "info")
        return _redirect_back_to_case(case_id, "case_overview")

    @app.get("/cases/<case_id>/archive")
    def export_case_archive(case_id: str):
        case = _load_case(app.config["STORAGE_DIR"], case_id)
        data = _export_case_archive(Path(case["dir"]), case_id)
        stem = f"apk-sentinel-case-{_slug(case['metadata'].get('source_name') or case_id)}-{case_id[:15]}"
        return send_file(
            BytesIO(data),
            download_name=f"{stem}.zip",
            mimetype="application/zip",
            as_attachment=True,
        )

    @app.get("/cases/<case_id>/report")
    def case_report(case_id: str):
        case = _load_case(app.config["STORAGE_DIR"], case_id)
        settings = _load_settings(app.config["STORAGE_DIR"])
        return render_template("dashboard/report.html", active="report", case=case, settings=settings)

    @app.post("/cases/<case_id>/report/export")
    def export_case_report(case_id: str):
        case = _load_case(app.config["STORAGE_DIR"], case_id)
        selected_keys = set(request.form.getlist("finding_key"))
        selection_submitted = request.form.get("selection_submitted") == "1"
        selected_findings = (
            [finding for finding in case["result"]["findings"] if finding.get("key") in selected_keys]
            if selection_submitted
            else list(case["result"]["findings"])
        )
        options = {
            "tester": request.form.get("tester", "").strip() or _load_settings(app.config["STORAGE_DIR"])["report_author"],
            "notes": request.form.get("notes", "").strip() or case["notes"].get("case_notes", ""),
            "include_indicators": request.form.get("include_indicators") == "1",
            "include_proxy": request.form.get("include_proxy") == "1",
        }
        stem = f"apk-sentinel-{_slug(case['metadata'].get('source_name') or case_id)}-{case_id[:15]}"
        data = _render_case_report_html(case, selected_findings, options).encode("utf-8")
        return send_file(
            BytesIO(data),
            download_name=f"{stem}.html",
            mimetype="text/html; charset=utf-8",
            as_attachment=True,
        )

    @app.post("/cases/<case_id>/delete")
    def delete_case(case_id: str):
        storage_dir = app.config["STORAGE_DIR"]
        case = _load_case(storage_dir, case_id)
        for session in case["dynamic"].get("sessions", []):
            app.config["PROXY_MANAGER"].stop(case_id, session.get("id", ""))

        case_dir = Path(case["dir"]).resolve()
        cases_root = (storage_dir / "cases").resolve()
        if not _is_relative_to(case_dir, cases_root):
            abort(404)

        shutil.rmtree(case_dir)
        flash(f"Deleted case {case['result']['profile'].get('file_name') or case_id}.", "info")
        return redirect(url_for("index"))

    @app.get("/cases/<case_id>/findings")
    def case_findings(case_id: str):
        case = _load_case(app.config["STORAGE_DIR"], case_id)
        severity = request.args.get("severity", "all")
        findings = _sorted_findings(case["result"]["findings"])
        if severity != "all":
            findings = [finding for finding in findings if finding.get("severity") == severity]
        return render_template(
            "dashboard/findings.html",
            active="findings",
            case=case,
            findings=findings,
            severity=severity,
            severities=["all", "critical", "high", "medium", "low", "info"],
        )

    @app.post("/cases/<case_id>/findings/<finding_key>/notes")
    def save_finding_note(case_id: str, finding_key: str):
        if not re.fullmatch(r"[a-f0-9]{16}", finding_key):
            abort(404)
        case = _load_case(app.config["STORAGE_DIR"], case_id)
        if not any(finding.get("key") == finding_key for finding in case["result"]["findings"]):
            abort(404)
        notes = _load_case_notes(Path(case["dir"]))
        finding_notes = notes.setdefault("findings", {})
        status = request.form.get("status", "open").strip().lower()
        if status not in FINDING_STATUSES:
            status = "open"
        finding_notes[finding_key] = {
            "status": status,
            "notes": request.form.get("notes", "").strip(),
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
        notes["updated_at"] = finding_notes[finding_key]["updated_at"]
        _write_case_notes(Path(case["dir"]), notes)
        flash("Finding note saved.", "info")
        return _redirect_back_to_case(case_id, "case_findings")

    @app.get("/cases/<case_id>/permissions")
    def case_permissions(case_id: str):
        case = _load_case(app.config["STORAGE_DIR"], case_id)
        findings = case["result"]["findings"]
        permission_findings = [
            finding for finding in findings if finding.get("rule_id") == "manifest.dangerous_permission"
        ]
        return render_template(
            "dashboard/permissions.html",
            active="permissions",
            case=case,
            permission_findings=permission_findings,
        )

    @app.get("/cases/<case_id>/components")
    def case_components(case_id: str):
        case = _load_case(app.config["STORAGE_DIR"], case_id)
        components = case["result"]["profile"].get("components", [])
        component_findings = [
            finding
            for finding in case["result"]["findings"]
            if finding.get("rule_id") in {"manifest.exported_component", "manifest.implicit_export"}
        ]
        return render_template(
            "dashboard/components.html",
            active="components",
            case=case,
            components=components,
            component_findings=component_findings,
        )

    @app.get("/cases/<case_id>/indicators")
    def case_indicators(case_id: str):
        case = _load_case(app.config["STORAGE_DIR"], case_id)
        category = request.args.get("category", "all")
        indicators = case["indicators"]
        if category != "all":
            indicators = [item for item in indicators if item.get("category") == category]
        categories = ["all"] + sorted({item["category"] for item in case["indicators"]})
        return render_template(
            "dashboard/indicators.html",
            active="indicators",
            case=case,
            indicators=indicators,
            category=category,
            categories=categories,
        )

    @app.get("/cases/<case_id>/intelligence")
    def case_intelligence(case_id: str):
        case = _load_case(app.config["STORAGE_DIR"], case_id)
        db = load_vuln_db(app.config["STORAGE_DIR"])
        return render_template("dashboard/case_intelligence.html", active="intelligence", case=case, db=db)

    @app.post("/cases/<case_id>/intelligence/update")
    def update_case_intelligence(case_id: str):
        case = _load_case(app.config["STORAGE_DIR"], case_id)
        result = update_osv_cache(app.config["STORAGE_DIR"], case["dependencies"])
        if result.get("error"):
            flash(f"OSV update failed: {result['error']}", "error")
        else:
            flash(f"OSV update complete: {result['queried']} package(s), {result['vulnerabilities']} vulnerability match(es).", "info")
        return redirect(url_for("case_intelligence", case_id=case_id))

    @app.get("/cases/<case_id>/dynamic")
    def case_dynamic(case_id: str):
        case = _load_case(app.config["STORAGE_DIR"], case_id)
        _attach_proxy_status(case, app.config["PROXY_MANAGER"])
        return render_template("dashboard/dynamic.html", active="dynamic", case=case)

    @app.post("/cases/<case_id>/dynamic/sessions")
    def create_dynamic_session(case_id: str):
        case = _load_case(app.config["STORAGE_DIR"], case_id)
        label = request.form.get("label", "").strip()
        host = request.form.get("proxy_host", "127.0.0.1").strip() or "127.0.0.1"
        try:
            port = int(request.form.get("proxy_port", "8088"))
        except ValueError:
            port = 8088
        notes = request.form.get("notes", "").strip()
        case["dynamic"]["sessions"].insert(0, make_dynamic_session(label, host, port, notes))
        _write_dynamic_state(case, case["dynamic"])
        return redirect(url_for("case_dynamic", case_id=case_id))

    @app.post("/cases/<case_id>/dynamic/proxy/start")
    def start_builtin_proxy(case_id: str):
        case = _load_case(app.config["STORAGE_DIR"], case_id)
        session_id = request.form.get("session_id", "")
        session = _find_session(case, session_id)
        if not session:
            flash("Choose a valid dynamic session first.", "error")
            return redirect(url_for("case_dynamic", case_id=case_id))

        try:
            port = int(session.get("proxy_port", 8088))
        except (TypeError, ValueError):
            port = 8088
        host = session.get("proxy_host") or "127.0.0.1"

        try:
            instance = app.config["PROXY_MANAGER"].start(case_id, session_id, host, port, Path(case["dir"]))
        except OSError as exc:
            flash(f"Proxy could not start on {host}:{port}: {exc}", "error")
            return redirect(url_for("case_dynamic", case_id=case_id))

        session["status"] = "running"
        session["proxy_host"] = instance.host
        session["proxy_port"] = instance.port
        session["proxy_started_at"] = instance.started_at
        _write_dynamic_state(case, case["dynamic"])
        flash(f"Built-in proxy listening on {instance.host}:{instance.port}.", "info")
        return redirect(url_for("case_dynamic", case_id=case_id))

    @app.post("/cases/<case_id>/dynamic/proxy/stop")
    def stop_builtin_proxy(case_id: str):
        case = _load_case(app.config["STORAGE_DIR"], case_id)
        session_id = request.form.get("session_id", "")
        session = _find_session(case, session_id)
        if not session:
            flash("Choose a valid dynamic session first.", "error")
            return redirect(url_for("case_dynamic", case_id=case_id))

        capture = app.config["PROXY_MANAGER"].stop(case_id, session_id)
        if capture is None:
            flash("That proxy session is not running in this dashboard process.", "error")
            session["status"] = "planned"
            _write_dynamic_state(case, case["dynamic"])
            return redirect(url_for("case_dynamic", case_id=case_id))

        session["status"] = "stopped"
        session["proxy_stopped_at"] = datetime.now(timezone.utc).isoformat()
        if capture["request_count"]:
            case["dynamic"]["captures"].insert(0, capture)
            flash(f"Proxy stopped and saved {capture['request_count']} captured request(s).", "info")
        else:
            flash("Proxy stopped. No requests were captured.", "info")
        _write_dynamic_state(case, case["dynamic"])
        return redirect(url_for("case_dynamic", case_id=case_id))

    @app.post("/cases/<case_id>/dynamic/captures")
    def import_dynamic_capture(case_id: str):
        case = _load_case(app.config["STORAGE_DIR"], case_id)
        upload = request.files.get("capture")
        if not upload or not upload.filename:
            flash("Choose a HAR or mitmproxy JSON capture first.", "error")
            return redirect(url_for("case_dynamic", case_id=case_id))

        captures_dir = Path(case["dir"]) / "captures"
        captures_dir.mkdir(parents=True, exist_ok=True)
        capture_path = captures_dir / f"{_timestamp()}-{secure_filename(upload.filename) or 'capture.json'}"
        upload.save(capture_path)
        try:
            capture = import_capture(capture_path, request.form.get("session_id") or None)
        except Exception as exc:
            flash(f"Capture import failed: {exc}", "error")
            return redirect(url_for("case_dynamic", case_id=case_id))
        case["dynamic"]["captures"].insert(0, capture)
        _write_dynamic_state(case, case["dynamic"])
        return redirect(url_for("case_dynamic", case_id=case_id))

    @app.get("/cases/<case_id>/files")
    def case_files(case_id: str):
        case = _load_case(app.config["STORAGE_DIR"], case_id)
        query = request.args.get("q", "").strip().lower()
        kind = request.args.get("kind", "all")
        view = request.args.get("view", "preview")
        deep = request.args.get("deep") == "1"
        selected_path = request.args.get("path")
        requested_dir = request.args.get("dir", "")
        current_dir = _normalize_browser_dir(requested_dir)
        if selected_path and not requested_dir and not query:
            current_dir = _entry_parent_dir(selected_path)
        files = _filter_files(
            case["files"],
            query=query,
            kind=kind,
            apk_path=Path(case["metadata"]["apk_path"]),
            deep=deep,
        )
        browser = _build_file_browser(files, current_dir=current_dir, search_mode=bool(query))
        kinds = ["all"] + sorted({entry["kind"] for entry in case["files"]})

        preview = None
        if selected_path:
            preview = _preview_entry(Path(case["metadata"]["apk_path"]), selected_path, view=view)
            preview["reviewed"] = selected_path in case["reviews"]

        return render_template(
            "dashboard/files.html",
            active="files",
            case=case,
            files=files,
            browser=browser,
            kinds=kinds,
            kind=kind,
            query=query,
            deep=deep,
            view=view,
            current_dir=current_dir,
            selected_path=selected_path,
            preview=preview,
        )

    @app.post("/cases/<case_id>/files/review")
    def review_entry(case_id: str):
        case = _load_case(app.config["STORAGE_DIR"], case_id)
        entry_path = request.form.get("path", "")
        if not _entry_exists(case["files"], entry_path):
            abort(404)
        reviews = _load_reviews(Path(case["dir"]))
        action = request.form.get("action", "review")
        if action == "unreview":
            reviews.pop(entry_path, None)
            flash("Removed review mark.", "info")
        else:
            reviews[entry_path] = datetime.now(timezone.utc).isoformat()
            flash("Marked file as reviewed.", "info")
        _write_reviews(Path(case["dir"]), reviews)
        return redirect(
            url_for(
                "case_files",
                case_id=case_id,
                q=request.form.get("q", ""),
                kind=request.form.get("kind", "all"),
                dir=request.form.get("dir", ""),
                path=entry_path,
                view=request.form.get("view", "preview"),
                deep=request.form.get("deep", "0"),
            )
        )

    @app.get("/cases/<case_id>/files/download")
    def download_entry(case_id: str):
        case = _load_case(app.config["STORAGE_DIR"], case_id)
        entry_path = request.args.get("path", "")
        if not _entry_exists(case["files"], entry_path):
            abort(404)
        with zipfile.ZipFile(case["metadata"]["apk_path"]) as archive:
            data = archive.read(entry_path)
        download_name = PurePosixPath(entry_path).name or "apk-entry.bin"
        return send_file(
            BytesIO(data),
            download_name=download_name,
            mimetype="application/octet-stream",
            as_attachment=True,
        )

    return app


def _storage_path(storage_dir: str | Path | None) -> Path:
    if storage_dir:
        return Path(storage_dir).resolve()
    return Path(os.environ.get("APK_SENTINEL_STORAGE", ".apk_sentinel")).resolve()


def _ensure_storage(storage_dir: Path) -> None:
    (storage_dir / "cases").mkdir(parents=True, exist_ok=True)
    (storage_dir / "incoming").mkdir(parents=True, exist_ok=True)
    (storage_dir / "proxy_lab").mkdir(parents=True, exist_ok=True)
    (storage_dir / "proxy_lab" / "ca").mkdir(parents=True, exist_ok=True)


def _load_proxy_lab(storage_dir: Path) -> dict:
    path = storage_dir / "proxy_lab.json"
    if path.exists():
        lab = _read_json(path)
    else:
        lab = {"sessions": [], "rules": [], "captures": []}
        _write_json(path, lab)
    lab.setdefault("sessions", [])
    lab.setdefault("rules", [])
    lab.setdefault("captures", [])
    lab.setdefault("replays", [])
    lab.setdefault("intercept_enabled", False)
    lab.setdefault("pending_intercepts", [])
    lab.setdefault("live_captures", [])
    return lab


def _write_proxy_lab(storage_dir: Path, lab: dict) -> None:
    _write_json(storage_dir / "proxy_lab.json", lab)


def _clear_proxy_history_files(storage_dir: Path) -> None:
    proxy_dir = (storage_dir / "proxy_lab" / "proxy").resolve()
    proxy_root = (storage_dir / "proxy_lab").resolve()
    if not _is_relative_to(proxy_dir, proxy_root) or not proxy_dir.exists():
        return
    for path in proxy_dir.glob("*.jsonl"):
        resolved = path.resolve()
        if _is_relative_to(resolved, proxy_dir) and resolved.is_file():
            resolved.unlink()


def _delete_proxy_session_file(storage_dir: Path, session_id: str) -> None:
    proxy_dir = (storage_dir / "proxy_lab" / "proxy").resolve()
    path = (proxy_dir / f"{session_id}.jsonl").resolve()
    if _is_relative_to(path, proxy_dir) and path.exists() and path.is_file():
        path.unlink()


def _create_case_from_path(source_path: Path, storage_dir: Path, original_name: str) -> str:
    result = scan_apk(source_path)
    profile = result.profile
    case_id = f"{_timestamp()}-{_slug(profile.package_name or Path(original_name).stem)}-{profile.sha256[:10]}"
    case_dir = storage_dir / "cases" / case_id
    case_dir.mkdir(parents=True, exist_ok=False)

    apk_copy = case_dir / "app.apk"
    shutil.copy2(source_path, apk_copy)
    profile.path = str(apk_copy)
    profile.file_name = original_name

    result_data = asdict(result)
    file_index = _index_apk(apk_copy)
    indicators = extract_indicators(apk_copy)
    dependencies = result_data.get("profile", {}).get("dependencies", [])
    metadata = {
        "id": case_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "source_name": original_name,
        "apk_path": str(apk_copy),
    }

    _write_json(case_dir / "result.json", result_data)
    _write_json(case_dir / "files.json", file_index)
    _write_json(case_dir / "indicators.json", indicators)
    _write_json(case_dir / "dependencies.json", dependencies)
    _write_json(case_dir / "dynamic.json", empty_dynamic_state())
    _write_json(case_dir / "case.json", metadata)
    return case_id


def _list_cases(storage_dir: Path) -> list[dict]:
    cases: list[dict] = []
    for case_dir in sorted((storage_dir / "cases").glob("*"), reverse=True):
        if not case_dir.is_dir():
            continue
        try:
            case = _load_case(storage_dir, case_dir.name)
        except (FileNotFoundError, json.JSONDecodeError, ValueError):
            continue
        cases.append(_case_summary(case))
    return sorted(cases, key=lambda item: item["created_at"], reverse=True)


def _load_case(storage_dir: Path, case_id: str) -> dict:
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", case_id):
        abort(404)

    case_dir = (storage_dir / "cases" / case_id).resolve()
    cases_root = (storage_dir / "cases").resolve()
    if not _is_relative_to(case_dir, cases_root) or not case_dir.is_dir():
        abort(404)

    metadata = _read_json(case_dir / "case.json")
    result = _read_json(case_dir / "result.json")
    files = _read_json(case_dir / "files.json")
    reviews = _load_reviews(case_dir)
    notes = _load_case_notes(case_dir)
    dependencies = _load_dependencies(case_dir, metadata)
    result.setdefault("profile", {}).setdefault("dependencies", dependencies)
    if not result["profile"].get("dependencies"):
        result["profile"]["dependencies"] = dependencies
    vuln_db = load_vuln_db(storage_dir)
    vuln_matches = match_vulnerabilities(dependencies, vuln_db)
    for entry in files:
        entry["reviewed"] = entry.get("path") in reviews
    base_findings = list(result.get("findings", []))
    vuln_findings = [vuln_match_to_finding(match) for match in vuln_matches]
    result["findings"] = _sorted_findings(
        [_attach_finding_metadata(enrich_finding_dict(finding), files, notes) for finding in [*base_findings, *vuln_findings]]
    )
    indicators = _load_indicators(case_dir, metadata)
    dynamic = _load_dynamic_state(case_dir)
    summary = _summarize_result(result)
    summary["indicator_count"] = len(indicators)
    summary["dynamic_capture_count"] = len(dynamic["captures"])
    summary["reviewed_file_count"] = len(reviews)
    summary["noted_finding_count"] = sum(1 for item in notes.get("findings", {}).values() if item.get("notes"))
    summary["dependency_count"] = len(dependencies)
    summary["vuln_match_count"] = len(vuln_matches)
    summary["external_finding_count"] = sum(1 for finding in result["findings"] if finding.get("finding_type") == "external vuln match")
    summary["static_signal_count"] = sum(1 for finding in result["findings"] if finding.get("finding_type") != "external vuln match")
    return {
        "id": case_id,
        "dir": str(case_dir),
        "metadata": metadata,
        "result": result,
        "files": files,
        "dependencies": dependencies,
        "vuln_matches": vuln_matches,
        "vuln_db": vuln_db,
        "indicators": indicators,
        "dynamic": dynamic,
        "reviews": reviews,
        "notes": notes,
        "summary": summary,
    }


def _load_indicators(case_dir: Path, metadata: dict) -> list[dict]:
    path = case_dir / "indicators.json"
    if path.exists():
        return _read_json(path)
    indicators = extract_indicators(metadata["apk_path"])
    _write_json(path, indicators)
    return indicators


def _load_dependencies(case_dir: Path, metadata: dict) -> list[dict]:
    path = case_dir / "dependencies.json"
    if path.exists():
        try:
            data = _read_json(path)
        except (json.JSONDecodeError, OSError):
            data = []
        if isinstance(data, list):
            return data
    apk_path = Path(metadata.get("apk_path") or case_dir / "app.apk")
    if not apk_path.exists():
        apk_path = case_dir / "app.apk"
    try:
        dependencies = extract_dependency_inventory(apk_path)
    except (OSError, zipfile.BadZipFile, ValueError):
        dependencies = []
    _write_json(path, dependencies)
    return dependencies


def _all_case_dependencies(storage_dir: Path) -> list[dict]:
    dependencies: dict[str, dict] = {}
    for case_dir in sorted((storage_dir / "cases").glob("*")):
        if not case_dir.is_dir():
            continue
        try:
            metadata = _read_json(case_dir / "case.json")
            for dependency in _load_dependencies(case_dir, metadata):
                key = "|".join(
                    [
                        dependency.get("ecosystem", ""),
                        dependency.get("name", ""),
                        dependency.get("version", ""),
                        dependency.get("purl", ""),
                    ]
                )
                dependencies.setdefault(key, dependency)
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            continue
    return sorted(dependencies.values(), key=lambda item: (item.get("ecosystem", ""), item.get("name", ""), item.get("version", "")))


def _load_dynamic_state(case_dir: Path) -> dict:
    path = case_dir / "dynamic.json"
    if path.exists():
        state = _read_json(path)
    else:
        state = empty_dynamic_state()
        _write_json(path, state)
    state.setdefault("sessions", [])
    state.setdefault("captures", [])
    return state


def _write_dynamic_state(case: dict, state: dict) -> None:
    _write_json(Path(case["dir"]) / "dynamic.json", state)


def _find_session(case: dict, session_id: str) -> dict | None:
    for session in case["dynamic"]["sessions"]:
        if session.get("id") == session_id:
            return session
    return None


def _find_lab_session(lab: dict, session_id: str) -> dict | None:
    for session in lab["sessions"]:
        if session.get("id") == session_id:
            return session
    return None


def _find_lab_request(lab: dict, capture_id: str, request_index: str | int) -> dict | None:
    try:
        index = int(request_index)
    except (TypeError, ValueError):
        return None

    for capture in [*lab.get("live_captures", []), *lab.get("captures", [])]:
        if capture.get("id") != capture_id:
            continue
        requests = capture.get("requests", [])
        if 0 <= index < len(requests):
            selected = dict(requests[index])
            selected["capture_id"] = capture_id
            selected["request_index"] = index
            selected["capture_name"] = capture.get("source_name")
            return selected
    return None


def _attach_proxy_status(case: dict, manager: CaptureProxyManager) -> None:
    for session in case["dynamic"]["sessions"]:
        status = manager.status(case["id"], session["id"])
        session["proxy_live"] = status
        if status["running"]:
            session["status"] = "running"


def _attach_proxy_lab_status(lab: dict, manager: CaptureProxyManager) -> None:
    running_sessions = 0
    live_request_count = 0
    active_proxies: list[str] = []
    for session in lab["sessions"]:
        status = manager.status("proxy-lab", session["id"])
        session["proxy_live"] = status
        if status["running"]:
            session["status"] = "running"
            running_sessions += 1
            live_request_count += status.get("request_count", 0)
            active_proxies.append(f"{status.get('host')}:{status.get('port')}")
    lab["pending_intercepts"] = manager.pending_intercepts("proxy-lab")
    lab["live_captures"] = manager.live_captures("proxy-lab")
    saved_request_count = sum(capture.get("request_count", 0) for capture in lab.get("captures", []))
    lab["summary"] = {
        "running_sessions": running_sessions,
        "live_request_count": live_request_count,
        "saved_request_count": saved_request_count,
        "pending_count": len(lab["pending_intercepts"]),
        "active_proxies": active_proxies,
    }


def _case_summary(case: dict) -> dict:
    profile = case["result"]["profile"]
    summary = case["summary"]
    return {
        "id": case["id"],
        "created_at": case["metadata"]["created_at"],
        "file_name": profile.get("file_name") or case["metadata"]["source_name"],
        "package_name": profile.get("package_name") or "Unknown",
        "sha256": profile.get("sha256", ""),
        "size_bytes": profile.get("size_bytes", 0),
        "target_sdk": profile.get("target_sdk") or "Unknown",
        "finding_count": summary["finding_count"],
        "indicator_count": summary.get("indicator_count", 0),
        "dynamic_capture_count": summary.get("dynamic_capture_count", 0),
        "reviewed_file_count": summary.get("reviewed_file_count", 0),
        "risk_posture": summary["risk_posture"],
        "static_risk_posture": summary.get("static_risk_posture", summary["risk_posture"]),
        "vuln_risk_posture": summary.get("vuln_risk_posture", "No matches"),
        "vuln_match_count": summary.get("vuln_match_count", 0),
        "static_signal_count": summary.get("static_signal_count", summary["finding_count"]),
        "external_finding_count": summary.get("external_finding_count", 0),
        "severity_counts": summary["severity_counts"],
    }


def _summarize_result(result: dict) -> dict:
    findings = result.get("findings", [])
    severity_counts = Counter(finding.get("severity", "info") for finding in findings)
    exploitability_counts = Counter(finding.get("exploitability", "needs validation") for finding in findings)
    static_counts = Counter(
        finding.get("severity", "info")
        for finding in findings
        if finding.get("finding_type") != "external vuln match"
    )
    external_counts = Counter(
        finding.get("severity", "info")
        for finding in findings
        if finding.get("finding_type") == "external vuln match"
    )
    risk_posture = _posture_from_counts(severity_counts, empty_label="Clean")
    static_risk_posture = _posture_from_counts(static_counts, empty_label="Clean")
    vuln_risk_posture = _posture_from_counts(external_counts, empty_label="No matches")
    return {
        "finding_count": len(findings),
        "risk_posture": risk_posture,
        "static_risk_posture": static_risk_posture,
        "vuln_risk_posture": vuln_risk_posture,
        "severity_counts": dict(severity_counts),
        "static_severity_counts": dict(static_counts),
        "external_severity_counts": dict(external_counts),
        "exploitability_counts": dict(exploitability_counts),
    }


def _posture_from_counts(counts: Counter, empty_label: str) -> str:
    for severity in ("critical", "high", "medium", "low", "info"):
        if counts[severity]:
            return severity.title()
    return empty_label


def _index_apk(apk_path: Path) -> list[dict]:
    entries: list[dict] = []
    with zipfile.ZipFile(apk_path) as archive:
        for info in archive.infolist():
            if info.is_dir():
                continue
            entries.append(
                {
                    "path": info.filename,
                    "kind": _classify_entry(info.filename),
                    "size": info.file_size,
                    "compressed_size": info.compress_size,
                    "previewable": _previewable(info.filename, info.file_size),
                    "safe_path": _safe_zip_path(info.filename),
                }
            )
    return sorted(entries, key=lambda item: (item["kind"], item["path"].lower()))


def _local_apks(project_dir: Path, storage_dir: Path) -> list[dict]:
    storage_dir = storage_dir.resolve()
    apks: list[dict] = []
    for path in sorted(project_dir.glob("*.apk")):
        resolved = path.resolve()
        if _is_relative_to(resolved, storage_dir):
            continue
        apks.append(
            {
                "name": path.name,
                "path": str(resolved),
                "size": path.stat().st_size,
            }
        )
    return apks


def _filter_files(files: list[dict], query: str, kind: str, apk_path: Path | None = None, deep: bool = False) -> list[dict]:
    filtered = [dict(entry) for entry in files]
    if kind != "all":
        filtered = [entry for entry in filtered if entry["kind"] == kind]
    if query:
        path_matches = [entry for entry in filtered if query in entry["path"].lower()]
        if deep and apk_path:
            deep_hits = _deep_search_entries(apk_path, filtered, query)
            seen = {entry["path"] for entry in path_matches}
            for entry in deep_hits:
                if entry["path"] not in seen:
                    path_matches.append(entry)
                    seen.add(entry["path"])
        filtered = path_matches
    return filtered


def _build_file_browser(files: list[dict], current_dir: str, search_mode: bool = False) -> dict:
    current_dir = _normalize_browser_dir(current_dir)
    if search_mode:
        rows = []
        for entry in files:
            row = dict(entry)
            row["type"] = "file"
            row["name"] = PurePosixPath(entry["path"]).name or entry["path"]
            row["parent"] = _entry_parent_dir(entry["path"])
            rows.append(row)
        return {
            "current_dir": current_dir,
            "parent_dir": _entry_parent_dir(current_dir),
            "breadcrumbs": _breadcrumbs(current_dir),
            "rows": rows,
            "search_mode": True,
            "file_count": len(rows),
            "folder_count": 0,
        }

    prefix = f"{current_dir}/" if current_dir else ""
    folders: dict[str, dict] = {}
    rows: list[dict] = []
    for entry in files:
        path = entry["path"]
        if prefix and not path.startswith(prefix):
            continue
        relative = path[len(prefix) :] if prefix else path
        if not relative:
            continue
        if "/" in relative:
            folder_name = relative.split("/", 1)[0]
            folder_path = f"{prefix}{folder_name}" if prefix else folder_name
            folder = folders.setdefault(
                folder_path,
                {
                    "type": "folder",
                    "name": folder_name,
                    "path": folder_path,
                    "kind": "folder",
                    "size": 0,
                    "file_count": 0,
                    "reviewed_count": 0,
                },
            )
            folder["size"] += int(entry.get("size") or 0)
            folder["file_count"] += 1
            if entry.get("reviewed"):
                folder["reviewed_count"] += 1
            continue

        row = dict(entry)
        row["type"] = "file"
        row["name"] = relative
        row["parent"] = current_dir
        rows.append(row)

    folder_rows = sorted(folders.values(), key=lambda item: item["name"].lower())
    file_rows = sorted(rows, key=lambda item: item["name"].lower())
    return {
        "current_dir": current_dir,
        "parent_dir": _entry_parent_dir(current_dir),
        "breadcrumbs": _breadcrumbs(current_dir),
        "rows": [*folder_rows, *file_rows],
        "search_mode": False,
        "file_count": len(file_rows),
        "folder_count": len(folder_rows),
    }


def _normalize_browser_dir(value: str | None) -> str:
    cleaned = (value or "").replace("\\", "/").strip("/")
    parts = [part for part in cleaned.split("/") if part and part != "."]
    safe_parts = [part for part in parts if part != ".."]
    return "/".join(safe_parts)


def _entry_parent_dir(path: str | None) -> str:
    cleaned = (path or "").replace("\\", "/").strip("/")
    if "/" not in cleaned:
        return ""
    return cleaned.rsplit("/", 1)[0]


def _breadcrumbs(current_dir: str) -> list[dict]:
    crumbs = [{"label": "APK root", "dir": ""}]
    if not current_dir:
        return crumbs
    parts = current_dir.split("/")
    for index, part in enumerate(parts):
        crumbs.append({"label": part, "dir": "/".join(parts[: index + 1])})
    return crumbs


def _preview_entry(apk_path: Path, entry_path: str, view: str = "preview") -> dict:
    with zipfile.ZipFile(apk_path) as archive:
        if entry_path not in archive.namelist():
            abort(404)
        info = archive.getinfo(entry_path)
        preview = {
            "path": entry_path,
            "kind": _classify_entry(entry_path),
            "size": info.file_size,
            "mode": "binary",
            "content": "",
            "truncated": False,
            "error": None,
        }

        if view == "strings":
            with archive.open(info) as handle:
                data = handle.read(STRING_PREVIEW_BYTES + 1)
            strings = _extract_strings(data[:STRING_PREVIEW_BYTES])
            preview["mode"] = "strings"
            preview["truncated"] = len(data) > STRING_PREVIEW_BYTES or info.file_size > STRING_PREVIEW_BYTES
            if len(strings) > MAX_STRING_LINES:
                preview["truncated"] = True
            preview["content"] = "\n".join(strings[:MAX_STRING_LINES]) or "(no printable strings found in preview window)"
            return preview

        suffix = PurePosixPath(entry_path).suffix.lower()
        if entry_path == "AndroidManifest.xml" or suffix == ".xml":
            if info.file_size <= XML_PREVIEW_BYTES:
                try:
                    root = parse_xml_bytes(archive.read(entry_path))
                    ET.indent(root, space="  ")
                    preview["mode"] = "xml"
                    preview["content"] = ET.tostring(root, encoding="unicode")
                    return preview
                except (AxmlParseError, ET.ParseError, UnicodeDecodeError) as exc:
                    preview["error"] = f"XML parser fallback: {exc}"
            else:
                preview["error"] = "XML preview skipped because the file is large."

        if _text_like(entry_path):
            with archive.open(info) as handle:
                data = handle.read(PREVIEW_BYTES + 1)
            preview["mode"] = "text"
            preview["truncated"] = len(data) > PREVIEW_BYTES or info.file_size > PREVIEW_BYTES
            preview["content"] = data[:PREVIEW_BYTES].decode("utf-8", errors="replace")
            return preview

        with archive.open(info) as handle:
            data = handle.read(HEX_PREVIEW_BYTES)
        preview["mode"] = "hex"
        preview["truncated"] = info.file_size > HEX_PREVIEW_BYTES
        preview["content"] = _hex_dump(data)
        return preview


def _sorted_findings(findings: list[dict]) -> list[dict]:
    return sorted(
        findings,
        key=lambda item: SEVERITY_ORDER.get(item.get("severity", "info"), 0),
        reverse=True,
    )


def _entry_exists(files: list[dict], entry_path: str) -> bool:
    return any(entry["path"] == entry_path for entry in files)


def _classify_entry(path: str) -> str:
    lower = path.lower()
    suffix = PurePosixPath(path).suffix.lower()
    if path == "AndroidManifest.xml":
        return "manifest"
    if lower == "resources.arsc":
        return "resources"
    if re.fullmatch(r"classes(\d*)\.dex", path):
        return "dex"
    if lower.startswith("lib/") and lower.endswith(".so"):
        return "native"
    if lower.startswith("meta-inf/"):
        return "signing"
    if lower.startswith("assets/"):
        return "asset"
    if lower.startswith("res/"):
        return "resource"
    if suffix in TEXT_EXTENSIONS:
        return "text"
    return "other"


def _previewable(path: str, size: int) -> bool:
    return path == "AndroidManifest.xml" or _text_like(path) or size > 0


def _text_like(path: str) -> bool:
    return PurePosixPath(path).suffix.lower() in TEXT_EXTENSIONS


def _safe_zip_path(path: str) -> bool:
    pure = PurePosixPath(path)
    return not pure.is_absolute() and ".." not in pure.parts


def _hex_dump(data: bytes) -> str:
    lines: list[str] = []
    for offset in range(0, len(data), 16):
        chunk = data[offset : offset + 16]
        hex_part = " ".join(f"{byte:02x}" for byte in chunk)
        ascii_part = "".join(chr(byte) if 32 <= byte < 127 else "." for byte in chunk)
        lines.append(f"{offset:08x}  {hex_part:<47}  {ascii_part}")
    return "\n".join(lines) or "(empty file)"


def _extract_strings(data: bytes, min_length: int = 4) -> list[str]:
    strings: list[str] = []
    seen: set[str] = set()

    def add(value: str) -> None:
        normalized = value.strip()
        if len(normalized) < min_length or normalized in seen:
            return
        seen.add(normalized)
        strings.append(normalized)

    pattern = rb"[ -~]{%d,}" % min_length
    for match in re.findall(pattern, data):
        add(match.decode("utf-8", errors="replace"))

    try:
        text16 = data.decode("utf-16le", errors="ignore")
    except UnicodeDecodeError:
        text16 = ""
    for match in re.findall(rf"[ -~]{{{min_length},}}", text16):
        add(match)

    return strings


def _deep_search_entries(apk_path: Path, entries: list[dict], query: str) -> list[dict]:
    hits: list[dict] = []
    searchable_kinds = {"manifest", "resource", "asset", "text"}
    try:
        archive = zipfile.ZipFile(apk_path)
    except zipfile.BadZipFile:
        return hits

    with archive:
        for entry in entries:
            if len(hits) >= MAX_DEEP_SEARCH_HITS:
                break
            if entry.get("kind") not in searchable_kinds and not _text_like(entry.get("path", "")):
                continue
            try:
                info = archive.getinfo(entry["path"])
            except KeyError:
                continue
            if info.file_size > STRING_SEARCH_BYTES:
                continue
            data = archive.read(info)[:STRING_SEARCH_BYTES]
            text = _entry_search_text(entry["path"], data)
            if query in text.lower():
                hit = dict(entry)
                hit["search_snippet"] = _search_snippet(text, query)
                hits.append(hit)
    return hits


def _entry_search_text(path: str, data: bytes) -> str:
    if path == "AndroidManifest.xml" or PurePosixPath(path).suffix.lower() == ".xml":
        try:
            root = parse_xml_bytes(data)
            return ET.tostring(root, encoding="unicode")
        except (AxmlParseError, ET.ParseError, UnicodeDecodeError):
            pass
    if _text_like(path):
        return data.decode("utf-8", errors="replace")
    return "\n".join(_extract_strings(data))


def _search_snippet(text: str, query: str, radius: int = 90) -> str:
    lower = text.lower()
    index = lower.find(query)
    if index < 0:
        return ""
    start = max(0, index - radius)
    end = min(len(text), index + len(query) + radius)
    snippet = text[start:end].replace("\r", "").replace("\n", " ")
    snippet = re.sub(r"\s+", " ", snippet).strip()
    prefix = "..." if start else ""
    suffix = "..." if end < len(text) else ""
    return f"{prefix}{snippet}{suffix}"


def _load_reviews(case_dir: Path) -> dict[str, str]:
    path = case_dir / "reviews.json"
    if not path.exists():
        return {}
    try:
        reviews = _read_json(path)
    except (json.JSONDecodeError, OSError):
        return {}
    if not isinstance(reviews, dict):
        return {}
    return {str(key): str(value) for key, value in reviews.items()}


def _write_reviews(case_dir: Path, reviews: dict[str, str]) -> None:
    _write_json(case_dir / "reviews.json", reviews)


def _load_case_notes(case_dir: Path) -> dict:
    path = case_dir / "notes.json"
    if path.exists():
        try:
            notes = _read_json(path)
        except (json.JSONDecodeError, OSError):
            notes = {}
    else:
        notes = {}
    if not isinstance(notes, dict):
        notes = {}
    notes.setdefault("case_notes", "")
    notes.setdefault("findings", {})
    notes.setdefault("updated_at", "")
    return notes


def _write_case_notes(case_dir: Path, notes: dict) -> None:
    notes.setdefault("case_notes", "")
    notes.setdefault("findings", {})
    notes.setdefault("updated_at", datetime.now(timezone.utc).isoformat())
    _write_json(case_dir / "notes.json", notes)


def _load_settings(storage_dir: Path) -> dict:
    path = storage_dir / "settings.json"
    if path.exists():
        try:
            raw = _read_json(path)
        except (json.JSONDecodeError, OSError):
            raw = {}
    else:
        raw = {}
    settings = dict(DEFAULT_SETTINGS)
    if isinstance(raw, dict):
        settings.update(raw)
    try:
        settings["default_proxy_port"] = int(settings.get("default_proxy_port", 8088))
    except (TypeError, ValueError):
        settings["default_proxy_port"] = 8088
    settings["default_proxy_port"] = max(1, min(settings["default_proxy_port"], 65535))
    settings["default_proxy_host"] = str(settings.get("default_proxy_host") or "127.0.0.1")
    settings["report_author"] = str(settings.get("report_author") or "")
    return settings


def _write_settings(storage_dir: Path, settings: dict) -> None:
    clean = {
        "report_author": str(settings.get("report_author") or ""),
        "default_proxy_host": str(settings.get("default_proxy_host") or "127.0.0.1"),
        "default_proxy_port": int(settings.get("default_proxy_port") or 8088),
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    _write_json(storage_dir / "settings.json", clean)


def _export_case_archive(case_dir: Path, case_id: str) -> bytes:
    buffer = BytesIO()
    manifest = {
        "archive_version": CASE_ARCHIVE_VERSION,
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "case_id": case_id,
        "tool": "APK Sentinel",
        "tool_version": __version__,
    }
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("archive.json", json.dumps(manifest, indent=2, sort_keys=True))
        for path in sorted(case_dir.rglob("*")):
            if not path.is_file():
                continue
            relative = path.relative_to(case_dir).as_posix()
            if relative == "archive.json":
                continue
            archive.write(path, relative)
    return buffer.getvalue()


def _import_case_archive(stream, storage_dir: Path, original_name: str) -> str:
    cases_root = storage_dir / "cases"
    with zipfile.ZipFile(stream) as archive:
        names = [info.filename for info in archive.infolist() if not info.is_dir()]
        for name in names:
            if not _safe_zip_path(name):
                raise ValueError(f"Unsafe archive path: {name}")
        if "case.json" not in names:
            raise ValueError("Archive is missing case.json.")
        metadata = json.loads(archive.read("case.json").decode("utf-8"))
        requested_id = _slug(str(metadata.get("id") or Path(original_name).stem))
        case_id = _unique_case_id(cases_root, requested_id)
        case_dir = cases_root / case_id
        case_dir.mkdir(parents=True, exist_ok=False)
        try:
            for info in archive.infolist():
                if info.is_dir() or info.filename == "archive.json":
                    continue
                target = case_dir.joinpath(*PurePosixPath(info.filename).parts).resolve()
                if not _is_relative_to(target, case_dir.resolve()):
                    raise ValueError(f"Unsafe archive path: {info.filename}")
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(info) as src, target.open("wb") as dst:
                    shutil.copyfileobj(src, dst)
            metadata_path = case_dir / "case.json"
            metadata = _read_json(metadata_path)
            if isinstance(metadata, dict):
                metadata["id"] = case_id
                metadata["apk_path"] = str(case_dir / "app.apk")
                metadata.setdefault("imported_at", datetime.now(timezone.utc).isoformat())
                _write_json(metadata_path, metadata)
            result_path = case_dir / "result.json"
            result = _read_json(result_path)
            if isinstance(result, dict):
                profile = result.setdefault("profile", {})
                if isinstance(profile, dict):
                    profile["path"] = str(case_dir / "app.apk")
                _write_json(result_path, result)
            _load_case(storage_dir, case_id)
        except Exception:
            shutil.rmtree(case_dir, ignore_errors=True)
            raise
    return case_id


def _unique_case_id(cases_root: Path, requested_id: str) -> str:
    case_id = requested_id or f"imported-{_timestamp()}"
    if not (cases_root / case_id).exists():
        return case_id
    suffix = _timestamp()
    candidate = f"{case_id}-{suffix}"
    counter = 2
    while (cases_root / candidate).exists():
        candidate = f"{case_id}-{suffix}-{counter}"
        counter += 1
    return candidate


def _redirect_back_to_case(case_id: str, default_endpoint: str):
    next_path = request.form.get("next", "")
    if next_path.startswith(f"/cases/{case_id}"):
        return redirect(next_path)
    return redirect(url_for(default_endpoint, case_id=case_id))


def _attach_finding_metadata(finding: dict, files: list[dict], notes: dict | None = None) -> dict:
    enriched = dict(finding)
    enriched["key"] = _finding_key(enriched)
    evidence_path = _finding_evidence_path(enriched, files)
    if evidence_path:
        enriched["evidence_path"] = evidence_path
    finding_note = (notes or {}).get("findings", {}).get(enriched["key"], {})
    enriched["tester_status"] = finding_note.get("status", "open")
    enriched["tester_notes"] = finding_note.get("notes", "")
    enriched["tester_notes_updated_at"] = finding_note.get("updated_at", "")
    return enriched


def _finding_key(finding: dict) -> str:
    identity = "|".join(
        [
            str(finding.get("rule_id", "")),
            str(finding.get("location", "")),
            str(finding.get("evidence", "")),
        ]
    )
    return sha1(identity.encode("utf-8", errors="replace")).hexdigest()[:16]


def _finding_evidence_path(finding: dict, files: list[dict]) -> str | None:
    paths = {entry["path"] for entry in files}
    location = str(finding.get("location") or "")
    evidence = str(finding.get("evidence") or "")
    for value in (location, evidence):
        if value in paths:
            return value
        if "AndroidManifest.xml" in value and "AndroidManifest.xml" in paths:
            return "AndroidManifest.xml"
        for path in paths:
            if path and path in value:
                return path
    if str(finding.get("rule_id", "")).startswith("manifest.") and "AndroidManifest.xml" in paths:
        return "AndroidManifest.xml"
    return None


def _render_case_report_html(case: dict, findings: list[dict], options: dict) -> str:
    profile = case["result"]["profile"]
    generated_at = datetime.now(timezone.utc).isoformat()
    tester = options.get("tester") or "Not specified"
    notes = options.get("notes") or "No tester notes provided."
    finding_cards = "\n".join(finding_card_html(finding, index + 1) for index, finding in enumerate(findings))
    if not finding_cards:
        finding_cards = '<p class="empty">No findings were selected for this report.</p>'

    indicator_section = ""
    if options.get("include_indicators"):
        indicator_section = _report_indicator_section(case.get("indicators", []))

    proxy_section = ""
    if options.get("include_proxy"):
        proxy_section = _report_proxy_section(case.get("dynamic", {}))
    intelligence_section = _report_intelligence_section(case.get("dependencies", []), case.get("vuln_matches", []))

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>APK Sentinel Case Report - {_h(profile.get('file_name'))}</title>
  <style>
{REPORT_BASE_CSS}
  </style>
</head>
<body>
<main>
  {REPORT_TOOLBAR_HTML}
  <section class="hero">
    <p>APK Sentinel Case Report</p>
    <h1>{_h(profile.get('file_name'))}</h1>
    <p>{_h(profile.get('package_name') or 'Package unknown')}</p>
    <div class="meta-grid">
      <div class="meta"><span>Generated</span><strong>{_h(generated_at)}</strong></div>
      <div class="meta"><span>Tester</span><strong>{_h(tester)}</strong></div>
      <div class="meta"><span>Selected Findings</span><strong>{len(findings)}</strong></div>
      <div class="meta"><span>SHA-256</span><strong>{_h(profile.get('sha256', ''))}</strong></div>
    </div>
  </section>

  <section class="panel">
    <h2>Tester Notes</h2>
    <p>{_h(notes)}</p>
  </section>

  <section>
    <h2>Selected Findings</h2>
    {finding_cards}
  </section>

  {indicator_section}
  {intelligence_section}
  {proxy_section}
</main>
</body>
</html>
"""


def _report_indicator_section(indicators: list[dict]) -> str:
    cards = "\n".join(
        f"""
  <article class="evidence-card {_h(item.get('severity', 'info'))}">
    <div class="evidence-head">
      <div class="badge-row">
        <span class="badge {_h(item.get('severity', 'info'))}">{_h(item.get('severity', ''))}</span>
        <span class="badge neutral">{_h(item.get('category', 'indicator'))}</span>
      </div>
      <h3>{_h(item.get('label', 'Indicator'))}</h3>
      <p class="muted">{_h(item.get('description', ''))}</p>
    </div>
    <div class="evidence-meta">
      <div><strong>Source</strong><p>{_h(item.get('path', ''))}{':' + _h(item.get('line')) if item.get('line') else ''}</p></div>
      <div><strong>Proof value</strong><code>{_h(item.get('value_preview', ''))}</code></div>
      <div><strong>Proof hash</strong><code>{_h(item.get('value_sha256', ''))}</code></div>
      <div><strong>Snippet</strong><pre class="proof">{_h(item.get('proof', ''))}</pre></div>
    </div>
  </article>"""
        for item in indicators
    )
    if not cards:
        cards = '<p class="empty">No indicators were available.</p>'
    return f"""
<section class="panel">
  <h2>Proof Snippets</h2>
  <div class="evidence-grid">{cards}</div>
</section>"""


def _report_intelligence_section(dependencies: list[dict], matches: list[dict]) -> str:
    if not dependencies and not matches:
        return ""
    match_cards = "\n".join(
        f"""
  <article class="evidence-card {_h(match.get('vulnerability', {}).get('severity', 'medium'))}">
    <div class="evidence-head">
      <div class="badge-row">
        <span class="badge {_h(match.get('vulnerability', {}).get('severity', 'medium'))}">{_h(match.get('vulnerability', {}).get('severity', 'medium'))}</span>
        <span class="badge neutral">{_h(match.get('source', 'OSV'))}</span>
      </div>
      <h3>{_h(match.get('vulnerability', {}).get('id', 'Vulnerability match'))}</h3>
      <p class="muted">{_h(match.get('vulnerability', {}).get('summary', ''))}</p>
    </div>
    <div class="evidence-meta">
      <div><strong>Package</strong><p>{_h(match.get('dependency', {}).get('name', ''))}@{_h(match.get('dependency', {}).get('version', ''))}</p></div>
      <div><strong>Evidence</strong><p>{_h(match.get('dependency', {}).get('evidence', ''))}</p></div>
      <div><strong>PURL</strong><code>{_h(match.get('dependency', {}).get('purl', ''))}</code></div>
    </div>
  </article>"""
        for match in matches
    )
    if not match_cards:
        match_cards = '<p class="empty">No cached vulnerability matches for the discovered package inventory.</p>'
    dependency_rows = "\n".join(
        "<tr>"
        f"<td>{_h(item.get('ecosystem', ''))}</td>"
        f"<td>{_h(item.get('name', ''))}</td>"
        f"<td>{_h(item.get('version', '') or 'unknown')}</td>"
        f"<td>{_h(item.get('confidence', ''))}</td>"
        f"<td>{_h(item.get('evidence', ''))}</td>"
        "</tr>"
        for item in dependencies[:80]
    )
    if not dependency_rows:
        dependency_rows = '<tr><td colspan="5">No dependencies were identified.</td></tr>'
    return f"""
<section class="panel">
  <h2>Vulnerability Intelligence</h2>
  <div class="evidence-grid">{match_cards}</div>
  <h3>Dependency Inventory</h3>
  <table>
    <thead><tr><th>Ecosystem</th><th>Name</th><th>Version</th><th>Confidence</th><th>Evidence</th></tr></thead>
    <tbody>{dependency_rows}</tbody>
  </table>
</section>"""


def _report_proxy_section(dynamic: dict) -> str:
    rows: list[str] = []
    for capture in dynamic.get("captures", [])[:6]:
        for item in capture.get("requests", [])[:10]:
            rows.append(
                "<tr>"
                f"<td>{_h(item.get('method', ''))}</td>"
                f"<td>{_h(item.get('host', ''))}</td>"
                f"<td>{_h(item.get('path') or item.get('url', ''))}</td>"
                f"<td>{_h(str(item.get('status') or 'n/a'))}</td>"
                f"<td>{_h(capture.get('source_name', 'capture'))}</td>"
                "</tr>"
            )
    body = "\n".join(rows) or '<tr><td colspan="5">No proxy captures were attached to this case.</td></tr>'
    return f"""
<section class="panel">
  <h2>Proxy Evidence</h2>
  <table class="proxy-table">
    <thead><tr><th>Method</th><th>Host</th><th>Path</th><th>Status</th><th>Capture</th></tr></thead>
    <tbody>{body}</tbody>
  </table>
</section>"""


def _h(value: object) -> str:
    return html_escape(str(value or ""), quote=True)


def _write_json(path: Path, data: object) -> None:
    path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")


def _read_json(path: Path) -> dict | list:
    return json.loads(path.read_text(encoding="utf-8"))


def _timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")


def _slug(value: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9_.-]+", "-", value).strip("-").lower()
    return slug[:48] or "apk"


def _format_bytes(size: int) -> str:
    units = ["B", "KB", "MB", "GB"]
    value = float(size)
    for unit in units:
        if value < 1024 or unit == units[-1]:
            return f"{value:.1f} {unit}" if unit != "B" else f"{int(value)} B"
        value /= 1024
    return f"{size} B"


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False
