from __future__ import annotations

import json
from collections import Counter
from dataclasses import asdict

from apk_sentinel.models import SEVERITY_ORDER, ScanResult
from apk_sentinel.report_template import BASE_CSS, REPORT_TOOLBAR_HTML, escape, finding_card_html, format_bytes


def render_json(result: ScanResult) -> str:
    return json.dumps(asdict(result), indent=2, sort_keys=True)


def render_html(result: ScanResult) -> str:
    profile = result.profile
    findings = sorted(result.findings, key=lambda item: SEVERITY_ORDER[item.severity], reverse=True)
    severity_counts = Counter(finding.severity for finding in findings)
    exploitability_counts = Counter(finding.exploitability for finding in findings)

    finding_cards = "\n".join(finding_card_html(asdict(finding), index + 1) for index, finding in enumerate(findings))
    if not finding_cards:
        finding_cards = '<p class="empty">No findings were produced.</p>'

    component_rows = "\n".join(
        "<tr>"
        f"<td>{escape(component.kind)}</td>"
        f"<td>{escape(component.name or '(anonymous)')}</td>"
        f"<td>{escape(_bool_text(component.exported))}</td>"
        f"<td>{escape(component.permission or 'none')}</td>"
        f"<td>{component.intent_filters}</td>"
        "</tr>"
        for component in profile.components
    ) or '<tr><td colspan="5">No components found in manifest.</td></tr>'

    permissions = "\n".join(f'<span class="badge neutral">{escape(permission)}</span>' for permission in profile.permissions)
    permissions = permissions or '<span class="badge info">None found</span>'

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>APK Sentinel Report - {escape(profile.file_name)}</title>
  <style>
{BASE_CSS}
    .scoreboard {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(135px, 1fr)); gap: 10px; }}
    .score {{ border: 1px solid var(--line); border-left: 6px solid var(--info); border-radius: 8px; padding: 12px; background: #fff; }}
    .score strong {{ display: block; font-size: 22px; line-height: 1; }}
    .score span {{ display: block; margin-top: 6px; color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: .05em; }}
    .score.critical {{ border-left-color: var(--critical); }}
    .score.high {{ border-left-color: var(--high); }}
    .score.medium {{ border-left-color: var(--medium); }}
    .score.low {{ border-left-color: var(--low); }}
    .score.info {{ border-left-color: var(--info); }}
    .pill-row {{ display: flex; flex-wrap: wrap; gap: 8px; }}
  </style>
</head>
<body>
<main>
  {REPORT_TOOLBAR_HTML}
  <section class="hero">
    <p>APK Sentinel Scan Report</p>
    <h1>{escape(profile.file_name)}</h1>
    <p>{escape(profile.package_name or 'Package unknown')} &middot; SHA-256 {escape(profile.sha256)}</p>
    <div class="meta-grid">
      <div class="meta"><span>Risk Posture</span><strong>{escape(_posture(findings))}</strong></div>
      <div class="meta"><span>Target SDK</span><strong>{escape(str(profile.target_sdk or 'Unknown'))}</strong></div>
      <div class="meta"><span>Min SDK</span><strong>{escape(str(profile.min_sdk or 'Unknown'))}</strong></div>
      <div class="meta"><span>Findings</span><strong>{len(findings)}</strong></div>
      <div class="meta"><span>Native Libraries</span><strong>{len(profile.native_libraries)}</strong></div>
      <div class="meta"><span>DEX Files</span><strong>{len(profile.dex_files)}</strong></div>
      <div class="meta"><span>APK Size</span><strong>{escape(format_bytes(profile.size_bytes))}</strong></div>
    </div>
  </section>

  <section class="panel">
    <h2>Severity Overview</h2>
    <div class="scoreboard">
      {_score_card('critical', severity_counts)}
      {_score_card('high', severity_counts)}
      {_score_card('medium', severity_counts)}
      {_score_card('low', severity_counts)}
      {_score_card('info', severity_counts)}
    </div>
  </section>

  <section class="panel">
    <h2>Exploitability Overview</h2>
    <div class="scoreboard">
      {_exploitability_card('high', exploitability_counts)}
      {_exploitability_card('medium', exploitability_counts)}
      {_exploitability_card('contextual', exploitability_counts)}
      {_exploitability_card('low', exploitability_counts)}
      {_exploitability_card('needs validation', exploitability_counts)}
    </div>
  </section>

  <section>
    <h2>Finding Triage</h2>
    {finding_cards}
  </section>

  <section class="panel">
    <h2>Manifest Components</h2>
    <table>
      <thead><tr><th>Kind</th><th>Name</th><th>Exported</th><th>Permission</th><th>Intent Filters</th></tr></thead>
      <tbody>{component_rows}</tbody>
    </table>
  </section>

  <section class="panel">
    <h2>Permissions</h2>
    <div class="pill-row">{permissions}</div>
  </section>
</main>
</body>
</html>
"""


def _score_card(severity: str, counts: Counter[str]) -> str:
    return (
        f'<div class="score {severity}">'
        f"<strong>{counts.get(severity, 0)}</strong>"
        f"<span>{escape(severity)}</span>"
        "</div>"
    )


def _exploitability_card(label: str, counts: Counter[str]) -> str:
    return (
        '<div class="score">'
        f"<strong>{counts.get(label, 0)}</strong>"
        f"<span>{escape(label)}</span>"
        "</div>"
    )


def _posture(findings: list) -> str:
    if any(finding.severity == "critical" for finding in findings):
        return "Critical"
    if any(finding.severity == "high" for finding in findings):
        return "High"
    if any(finding.severity == "medium" for finding in findings):
        return "Medium"
    if findings:
        return "Low"
    return "Clean"


def _bool_text(value: bool | None) -> str:
    if value is None:
        return "not declared"
    return "true" if value else "false"
