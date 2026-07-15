from __future__ import annotations

import hashlib
import re
import zipfile
from pathlib import Path, PurePosixPath
import xml.etree.ElementTree as ET

from apk_sentinel.axml import AxmlParseError, parse_xml_bytes
from apk_sentinel.secret_patterns import IGNORED_URL_HOSTS, SECRET_PATTERNS as PATTERNS
from apk_sentinel.secret_patterns import SecretPattern as IndicatorPattern
from apk_sentinel.secret_patterns import mask as _mask
from apk_sentinel.secret_patterns import url_host

MAX_FILE_BYTES = 1024 * 1024
MAX_INDICATORS = 1000
MAX_PER_FILE = 80

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

__all__ = ["IndicatorPattern", "PATTERNS", "extract_indicators", "url_host"]


def extract_indicators(apk_path: str | Path) -> list[dict]:
    apk = Path(apk_path)
    indicators: list[dict] = []
    seen: set[tuple[str, str, str]] = set()

    with zipfile.ZipFile(apk) as archive:
        for info in archive.infolist():
            if info.is_dir() or info.file_size > MAX_FILE_BYTES:
                continue
            if not _is_candidate(info.filename):
                continue

            text = _read_entry_text(archive, info)
            if text is None:
                continue

            per_file = 0
            for pattern in PATTERNS:
                for match in pattern.pattern.finditer(text):
                    if _should_skip_match(pattern, match):
                        continue
                    value = match.group(0)
                    dedupe_key = (pattern.label, info.filename, value)
                    if dedupe_key in seen:
                        continue
                    seen.add(dedupe_key)
                    indicators.append(_indicator(pattern, info.filename, text, match))
                    per_file += 1
                    if per_file >= MAX_PER_FILE or len(indicators) >= MAX_INDICATORS:
                        break
                if per_file >= MAX_PER_FILE or len(indicators) >= MAX_INDICATORS:
                    break
            if len(indicators) >= MAX_INDICATORS:
                break

    return sorted(indicators, key=lambda item: (_severity_rank(item["severity"]), item["path"], item["label"]))


def _read_entry_text(archive: zipfile.ZipFile, info: zipfile.ZipInfo) -> str | None:
    data = archive.read(info)
    suffix = PurePosixPath(info.filename).suffix.lower()
    if info.filename == "AndroidManifest.xml" or suffix == ".xml":
        try:
            root = parse_xml_bytes(data)
            ET.indent(root, space="  ")
            return ET.tostring(root, encoding="unicode")
        except (AxmlParseError, ET.ParseError, UnicodeDecodeError):
            pass

    try:
        return data.decode("utf-8", errors="ignore")
    except UnicodeDecodeError:
        return None


def _indicator(pattern: IndicatorPattern, path: str, text: str, match: re.Match[str]) -> dict:
    value = match.group(0)
    return {
        "id": hashlib.sha256(f"{pattern.label}:{path}:{match.start()}:{value}".encode("utf-8")).hexdigest()[:16],
        "label": pattern.label,
        "category": pattern.category,
        "severity": pattern.severity,
        "confidence": pattern.confidence,
        "description": pattern.description,
        "recommendation": pattern.recommendation,
        "value_preview": _mask(value) if pattern.redact else value,
        "value_sha256": hashlib.sha256(value.encode("utf-8", errors="ignore")).hexdigest(),
        "path": path,
        "line": text.count("\n", 0, match.start()) + 1,
        "offset": match.start(),
        "proof": _snippet(text, match, pattern.redact),
        "redacted": pattern.redact,
    }


def _snippet(text: str, match: re.Match[str], redact: bool) -> str:
    start = max(0, match.start() - 120)
    end = min(len(text), match.end() + 120)
    snippet = text[start:end].replace("\r", "")
    value = match.group(0)
    if redact:
        snippet = snippet.replace(value, _mask(value))
    return _redact_embedded_secrets(snippet).strip()


def _redact_embedded_secrets(snippet: str) -> str:
    redacted = snippet
    for pattern in PATTERNS:
        if not pattern.redact:
            continue
        redacted = pattern.pattern.sub(lambda match: _mask(match.group(0)), redacted)
    return redacted


def _should_skip_match(pattern: IndicatorPattern, match: re.Match[str]) -> bool:
    if pattern.category != "network":
        return False
    host = url_host(match.group(0))
    return host in IGNORED_URL_HOSTS


def _is_candidate(path: str) -> bool:
    suffix = PurePosixPath(path).suffix.lower()
    return path == "AndroidManifest.xml" or suffix in TEXT_EXTENSIONS


def _severity_rank(severity: str) -> int:
    return {
        "critical": 0,
        "high": 1,
        "medium": 2,
        "low": 3,
        "info": 4,
    }.get(severity, 5)
