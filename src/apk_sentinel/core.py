from __future__ import annotations

from pathlib import Path

from apk_sentinel.apk import read_apk
from apk_sentinel.models import ScanResult
from apk_sentinel.rules import evaluate_rules


def scan_apk(path: str | Path) -> ScanResult:
    profile = read_apk(Path(path))
    findings = evaluate_rules(profile)
    return ScanResult(profile=profile, findings=findings)

