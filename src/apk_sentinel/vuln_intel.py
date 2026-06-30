from __future__ import annotations

import json
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

OSV_QUERY_BATCH_URL = "https://api.osv.dev/v1/querybatch"


def empty_vuln_db() -> dict:
    return {
        "schema": 1,
        "updated_at": "",
        "sources": {"osv": {"status": "never", "updated_at": "", "error": ""}},
        "packages": {},
    }


def load_vuln_db(storage_dir: Path) -> dict:
    path = storage_dir / "vuln_db.json"
    if not path.exists():
        return empty_vuln_db()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return empty_vuln_db()
    if not isinstance(data, dict):
        return empty_vuln_db()
    clean = empty_vuln_db()
    clean.update(data)
    clean.setdefault("sources", {}).setdefault("osv", {"status": "never", "updated_at": "", "error": ""})
    clean.setdefault("packages", {})
    return clean


def save_vuln_db(storage_dir: Path, db: dict) -> None:
    storage_dir.mkdir(parents=True, exist_ok=True)
    (storage_dir / "vuln_db.json").write_text(json.dumps(db, indent=2, sort_keys=True), encoding="utf-8")


def update_osv_cache(storage_dir: Path, dependencies: list[dict], timeout: int = 20) -> dict:
    db = load_vuln_db(storage_dir)
    queries, query_keys = _osv_queries(dependencies)
    now = datetime.now(timezone.utc).isoformat()
    if not queries:
        db["updated_at"] = now
        db["sources"]["osv"] = {"status": "skipped", "updated_at": now, "error": "No Maven package versions discovered."}
        save_vuln_db(storage_dir, db)
        return {"queried": 0, "vulnerabilities": 0, "error": ""}

    request = urllib.request.Request(
        OSV_QUERY_BATCH_URL,
        data=json.dumps({"queries": queries}).encode("utf-8"),
        headers={"Content-Type": "application/json", "User-Agent": "APK-Sentinel/1.0"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError) as exc:
        db["sources"]["osv"] = {"status": "failed", "updated_at": now, "error": str(exc)}
        save_vuln_db(storage_dir, db)
        return {"queried": len(queries), "vulnerabilities": 0, "error": str(exc)}

    packages = db.setdefault("packages", {})
    vuln_count = 0
    for key, result in zip(query_keys, payload.get("results", [])):
        vulns = [_normalize_osv_vuln(vuln) for vuln in result.get("vulns", [])]
        vuln_count += len(vulns)
        packages[key["cache_key"]] = {
            "source": "OSV",
            "ecosystem": key["ecosystem"],
            "name": key["name"],
            "version": key["version"],
            "purl": key["purl"],
            "queried_at": now,
            "vulnerabilities": vulns,
        }

    db["updated_at"] = now
    db["sources"]["osv"] = {"status": "ok", "updated_at": now, "error": ""}
    save_vuln_db(storage_dir, db)
    return {"queried": len(queries), "vulnerabilities": vuln_count, "error": ""}


def match_vulnerabilities(dependencies: list[dict], db: dict) -> list[dict]:
    packages = db.get("packages", {}) if isinstance(db, dict) else {}
    matches: list[dict] = []
    for dependency in dependencies:
        cache_key = package_cache_key(dependency)
        entry = packages.get(cache_key)
        if not entry:
            continue
        for vuln in entry.get("vulnerabilities", []):
            matches.append(
                {
                    "dependency": dependency,
                    "vulnerability": vuln,
                    "source": entry.get("source", "OSV"),
                    "queried_at": entry.get("queried_at", ""),
                }
            )
    return sorted(matches, key=lambda item: (_severity_rank(item["vulnerability"].get("severity", "medium")), item["vulnerability"].get("id", "")))


def vuln_match_to_finding(match: dict) -> dict:
    dependency = match["dependency"]
    vuln = match["vulnerability"]
    vuln_id = vuln.get("id", "OSV")
    package_name = dependency.get("name", "unknown package")
    version = dependency.get("version") or "unknown version"
    severity = vuln.get("severity") or "high"
    references = [{"label": ref.get("type") or "reference", "url": ref.get("url", "")} for ref in vuln.get("references", [])[:5] if ref.get("url")]
    if not references:
        references = [{"label": "OSV advisory", "url": f"https://osv.dev/vulnerability/{vuln_id}"}]
    return {
        "rule_id": "vuln.osv_package",
        "title": f"Known vulnerability in {package_name}",
        "severity": severity,
        "description": vuln.get("summary") or f"{package_name} {version} matched a vulnerability record.",
        "evidence": f"{package_name}@{version} matched {vuln_id} from {match.get('source', 'OSV')}",
        "recommendation": "Upgrade the vulnerable dependency, remove it if unused, or document a compensating control when the vulnerable code path is unreachable.",
        "exploitability": "external intelligence",
        "impact": vuln.get("details") or "Impact depends on the vulnerable component and whether the affected code path is reachable in the app.",
        "attack_path": "Exploitability depends on whether attacker-controlled input can reach the vulnerable library code path in this APK.",
        "hardening": "Upgrade to a fixed version, reduce exposed attack surface, and validate the vulnerable feature is unreachable before downgrading severity.",
        "location": dependency.get("evidence") or "dependency inventory",
        "confidence": "high" if dependency.get("version") else "medium",
        "evidence_quality": f"External vuln match from {match.get('source', 'OSV')} using package/version evidence {dependency.get('evidence', '')}.",
        "exploitation_chain": [
            f"Confirm the APK includes {package_name} version {version} from {dependency.get('evidence', 'inventory evidence')}.",
            f"Review {vuln_id} and identify the affected API, feature, or native entry point.",
            "Use decompiled code, runtime traces, or proxy evidence to determine whether app-controlled or attacker-controlled input reaches the vulnerable path.",
            "Report as confirmed only when reachability and impact are validated; otherwise keep it as a high-confidence dependency risk.",
        ],
        "references": references,
        "vulnerability_id": vuln_id,
        "dependency_purl": dependency.get("purl", ""),
        "finding_type": "external vuln match",
        "masvs": ["MASVS-CODE"],
    }


def package_cache_key(dependency: dict) -> str:
    return "|".join(
        [
            dependency.get("ecosystem", ""),
            dependency.get("name", ""),
            dependency.get("version", ""),
            dependency.get("purl", ""),
        ]
    )


def _osv_queries(dependencies: list[dict]) -> tuple[list[dict], list[dict]]:
    queries: list[dict] = []
    keys: list[dict] = []
    seen: set[str] = set()
    for dependency in dependencies:
        ecosystem = dependency.get("ecosystem")
        name = dependency.get("name")
        version = dependency.get("version")
        if ecosystem != "Maven" or not name or not version:
            continue
        cache_key = package_cache_key(dependency)
        if cache_key in seen:
            continue
        seen.add(cache_key)
        queries.append({"package": {"ecosystem": ecosystem, "name": name}, "version": version})
        keys.append(
            {
                "cache_key": cache_key,
                "ecosystem": ecosystem,
                "name": name,
                "version": version,
                "purl": dependency.get("purl", ""),
            }
        )
    return queries, keys


def _normalize_osv_vuln(vuln: dict) -> dict:
    aliases = vuln.get("aliases", [])
    severity = _severity_from_osv(vuln)
    return {
        "id": vuln.get("id", ""),
        "aliases": aliases,
        "summary": vuln.get("summary", ""),
        "details": _shorten(vuln.get("details", ""), 1600),
        "severity": severity,
        "published": vuln.get("published", ""),
        "modified": vuln.get("modified", ""),
        "references": vuln.get("references", []),
    }


def _severity_from_osv(vuln: dict) -> str:
    severities = vuln.get("severity") or []
    scores: list[float] = []
    for item in severities:
        score = _cvss_score(str(item.get("score", "")))
        if score is not None:
            scores.append(score)
    if scores:
        score = max(scores)
        if score >= 9:
            return "critical"
        if score >= 7:
            return "high"
        if score >= 4:
            return "medium"
        return "low"
    database_specific = vuln.get("database_specific") or {}
    sev = str(database_specific.get("severity", "")).lower()
    if sev in {"critical", "high", "medium", "low"}:
        return sev
    return "high" if any(str(alias).startswith("CVE-") for alias in vuln.get("aliases", [])) else "medium"


def _cvss_score(value: str) -> float | None:
    if "/AV:" in value or value.startswith("CVSS:"):
        return None
    try:
        return float(value)
    except ValueError:
        return None


def _severity_rank(severity: str) -> int:
    return {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(severity, 5)


def _shorten(value: str, limit: int) -> str:
    text = str(value or "").strip()
    if len(text) <= limit:
        return text
    return text[: limit - 1].rstrip() + "..."
