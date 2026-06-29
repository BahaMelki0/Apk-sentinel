from __future__ import annotations

import html
import json
from collections import Counter
from dataclasses import asdict

from apk_sentinel.models import SEVERITY_ORDER, ScanResult


def render_json(result: ScanResult) -> str:
    return json.dumps(asdict(result), indent=2, sort_keys=True)


def render_html(result: ScanResult) -> str:
    profile = result.profile
    findings = sorted(result.findings, key=lambda item: SEVERITY_ORDER[item.severity], reverse=True)
    severity_counts = Counter(finding.severity for finding in findings)
    exploitability_counts = Counter(finding.exploitability for finding in findings)

    finding_cards = "\n".join(_finding_card(finding, index + 1) for index, finding in enumerate(findings))
    if not finding_cards:
        finding_cards = '<div class="empty">No findings were produced.</div>'

    component_rows = "\n".join(
        "<tr>"
        f"<td>{_e(component.kind)}</td>"
        f"<td>{_e(component.name or '(anonymous)')}</td>"
        f"<td>{_e(_bool_text(component.exported))}</td>"
        f"<td>{_e(component.permission or 'none')}</td>"
        f"<td>{component.intent_filters}</td>"
        "</tr>"
        for component in profile.components
    ) or '<tr><td colspan="5">No components found in manifest.</td></tr>'

    permissions = "\n".join(f'<span class="pill">{_e(permission)}</span>' for permission in profile.permissions)
    permissions = permissions or '<span class="pill muted-pill">None found</span>'

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>APK Sentinel Report - {_e(profile.file_name)}</title>
  <style>
    :root {{
      color-scheme: light;
      --page: #f4f6f8;
      --panel: #ffffff;
      --ink: #17202a;
      --soft-ink: #52606d;
      --line: #d7dee8;
      --brand: #0f766e;
      --critical: #7f1d1d;
      --high: #c2410c;
      --medium: #b7791f;
      --low: #2563eb;
      --info: #64748b;
      --good: #15803d;
      --shadow: 0 14px 34px rgba(22, 32, 42, .08);
    }}
    * {{
      box-sizing: border-box;
    }}
    body {{
      margin: 0;
      background: var(--page);
      color: var(--ink);
      font: 14px/1.55 system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }}
    main {{
      max-width: 1180px;
      margin: 0 auto;
      padding: 28px 18px 48px;
    }}
    .hero {{
      background: #111827;
      color: #f8fafc;
      border-radius: 8px;
      padding: 24px;
      box-shadow: var(--shadow);
    }}
    .hero-top {{
      display: flex;
      align-items: flex-start;
      justify-content: space-between;
      gap: 18px;
      flex-wrap: wrap;
    }}
    .eyebrow {{
      margin: 0 0 6px;
      color: #99f6e4;
      font-size: 12px;
      font-weight: 700;
      letter-spacing: .08em;
      text-transform: uppercase;
    }}
    h1, h2, h3, p {{
      margin-top: 0;
    }}
    h1 {{
      margin-bottom: 6px;
      font-size: 30px;
      line-height: 1.15;
      overflow-wrap: anywhere;
    }}
    h2 {{
      margin-bottom: 14px;
      font-size: 20px;
      line-height: 1.2;
    }}
    h3 {{
      margin-bottom: 8px;
      font-size: 18px;
      line-height: 1.25;
      overflow-wrap: anywhere;
    }}
    .muted {{
      color: var(--soft-ink);
    }}
    .hero .muted {{
      color: #cbd5e1;
    }}
    .posture {{
      min-width: 190px;
      border: 1px solid rgba(255,255,255,.18);
      border-radius: 8px;
      padding: 14px 16px;
      background: rgba(255,255,255,.07);
    }}
    .posture strong {{
      display: block;
      font-size: 12px;
      letter-spacing: .08em;
      text-transform: uppercase;
      color: #bfdbfe;
    }}
    .posture span {{
      display: block;
      margin-top: 4px;
      font-size: 24px;
      font-weight: 800;
    }}
    .summary {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 10px;
      margin-top: 22px;
    }}
    .metric {{
      min-width: 0;
      border: 1px solid rgba(255,255,255,.16);
      border-radius: 8px;
      padding: 12px;
      background: rgba(255,255,255,.06);
    }}
    .metric strong {{
      display: block;
      color: #bfdbfe;
      font-size: 11px;
      letter-spacing: .07em;
      text-transform: uppercase;
    }}
    .metric span {{
      display: block;
      margin-top: 4px;
      overflow-wrap: anywhere;
      color: #f8fafc;
      font-size: 15px;
      font-weight: 650;
    }}
    section {{
      margin-top: 22px;
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 20px;
      box-shadow: 0 8px 22px rgba(22, 32, 42, .04);
    }}
    .scoreboard {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(135px, 1fr));
      gap: 10px;
    }}
    .score {{
      border: 1px solid var(--line);
      border-left: 6px solid var(--info);
      border-radius: 8px;
      padding: 12px;
      background: #fff;
    }}
    .score strong {{
      display: block;
      font-size: 22px;
      line-height: 1;
    }}
    .score span {{
      display: block;
      margin-top: 6px;
      color: var(--soft-ink);
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: .05em;
    }}
    .score.critical {{ border-left-color: var(--critical); }}
    .score.high {{ border-left-color: var(--high); }}
    .score.medium {{ border-left-color: var(--medium); }}
    .score.low {{ border-left-color: var(--low); }}
    .score.info {{ border-left-color: var(--info); }}
    .finding-list {{
      display: grid;
      gap: 14px;
    }}
    .finding {{
      border: 1px solid var(--line);
      border-left: 7px solid var(--info);
      border-radius: 8px;
      background: #fff;
      overflow: hidden;
    }}
    .finding.critical {{ border-left-color: var(--critical); }}
    .finding.high {{ border-left-color: var(--high); }}
    .finding.medium {{ border-left-color: var(--medium); }}
    .finding.low {{ border-left-color: var(--low); }}
    .finding.info {{ border-left-color: var(--info); }}
    .finding-head {{
      display: grid;
      grid-template-columns: 1fr auto;
      gap: 16px;
      padding: 18px;
      border-bottom: 1px solid var(--line);
      background: #fbfcfe;
    }}
    .badge-row {{
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin-bottom: 10px;
    }}
    .badge {{
      display: inline-flex;
      align-items: center;
      min-height: 24px;
      border-radius: 999px;
      padding: 3px 9px;
      color: #fff;
      font-size: 12px;
      font-weight: 800;
      letter-spacing: .04em;
      text-transform: uppercase;
    }}
    .badge.critical {{ background: var(--critical); }}
    .badge.high {{ background: var(--high); }}
    .badge.medium {{ background: var(--medium); }}
    .badge.low {{ background: var(--low); }}
    .badge.info {{ background: var(--info); }}
    .badge.exploit {{
      background: #0f766e;
    }}
    .rule-id {{
      align-self: start;
      border: 1px solid var(--line);
      border-radius: 6px;
      padding: 6px 8px;
      color: var(--soft-ink);
      background: #fff;
      font-size: 12px;
      overflow-wrap: anywhere;
      max-width: 260px;
    }}
    .finding-body {{
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 0;
    }}
    .cell {{
      min-width: 0;
      padding: 16px 18px;
      border-bottom: 1px solid var(--line);
    }}
    .cell:nth-child(odd) {{
      border-right: 1px solid var(--line);
    }}
    .cell strong {{
      display: block;
      margin-bottom: 6px;
      color: #334155;
      font-size: 12px;
      letter-spacing: .06em;
      text-transform: uppercase;
    }}
    .cell p {{
      margin-bottom: 0;
      overflow-wrap: anywhere;
    }}
    .cell.full {{
      grid-column: 1 / -1;
      border-right: 0;
    }}
    .finding-body .cell:nth-last-child(-n+2) {{
      border-bottom: 0;
    }}
    .finding-body .cell.full:last-child {{
      border-bottom: 0;
    }}
    .pill-row {{
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
    }}
    .pill {{
      display: inline-flex;
      align-items: center;
      border: 1px solid #c7d2fe;
      border-radius: 999px;
      padding: 4px 9px;
      background: #eef2ff;
      color: #1e3a8a;
      font-size: 12px;
      font-weight: 650;
      overflow-wrap: anywhere;
      max-width: 100%;
    }}
    .muted-pill {{
      border-color: var(--line);
      background: #f8fafc;
      color: var(--soft-ink);
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      table-layout: fixed;
    }}
    th, td {{
      text-align: left;
      vertical-align: top;
      border-bottom: 1px solid var(--line);
      padding: 10px 8px;
      overflow-wrap: anywhere;
    }}
    th {{
      color: var(--soft-ink);
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: .05em;
    }}
    tr:last-child td {{
      border-bottom: 0;
    }}
    .empty {{
      border: 1px dashed var(--line);
      border-radius: 8px;
      padding: 18px;
      color: var(--soft-ink);
      background: #f8fafc;
    }}
    @media (max-width: 760px) {{
      main {{
        padding: 14px 10px 36px;
      }}
      .hero, section {{
        padding: 16px;
      }}
      .finding-head, .finding-body {{
        display: block;
      }}
      .rule-id {{
        margin-top: 12px;
        max-width: none;
      }}
      .cell, .cell:nth-child(odd) {{
        border-right: 0;
        border-bottom: 1px solid var(--line);
      }}
      .finding-body .cell:last-child {{
        border-bottom: 0;
      }}
    }}
  </style>
</head>
<body>
<main>
  <header class="hero">
    <div class="hero-top">
      <div>
        <p class="eyebrow">APK Sentinel</p>
        <h1>{_e(profile.file_name)}</h1>
        <p class="muted">{_e(profile.package_name or 'Package unknown')} · SHA-256 {_e(profile.sha256)}</p>
      </div>
      <div class="posture">
        <strong>Risk Posture</strong>
        <span>{_e(_posture(findings))}</span>
      </div>
    </div>
    <div class="summary">
      <div class="metric"><strong>Target SDK</strong><span>{_e(str(profile.target_sdk or 'Unknown'))}</span></div>
      <div class="metric"><strong>Min SDK</strong><span>{_e(str(profile.min_sdk or 'Unknown'))}</span></div>
      <div class="metric"><strong>Findings</strong><span>{len(findings)}</span></div>
      <div class="metric"><strong>Native Libraries</strong><span>{len(profile.native_libraries)}</span></div>
      <div class="metric"><strong>DEX Files</strong><span>{len(profile.dex_files)}</span></div>
      <div class="metric"><strong>APK Size</strong><span>{_e(_format_bytes(profile.size_bytes))}</span></div>
    </div>
  </header>

  <section>
    <h2>Severity Overview</h2>
    <div class="scoreboard">
      {_score_card('critical', severity_counts)}
      {_score_card('high', severity_counts)}
      {_score_card('medium', severity_counts)}
      {_score_card('low', severity_counts)}
      {_score_card('info', severity_counts)}
    </div>
  </section>

  <section>
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
    <div class="finding-list">{finding_cards}</div>
  </section>

  <section>
    <h2>Manifest Components</h2>
    <table>
      <thead><tr><th>Kind</th><th>Name</th><th>Exported</th><th>Permission</th><th>Intent Filters</th></tr></thead>
      <tbody>{component_rows}</tbody>
    </table>
  </section>

  <section>
    <h2>Permissions</h2>
    <div class="pill-row">{permissions}</div>
  </section>
</main>
</body>
</html>
"""


def _finding_card(finding, number: int) -> str:
    hardening = finding.hardening or finding.recommendation
    chain = finding.exploitation_chain or [finding.attack_path]
    chain_items = "\n".join(f"<li>{_e(step)}</li>" for step in chain)
    references = finding.references or []
    reference_items = " ".join(
        f'<a href="{_e(item.get("url", ""))}">{_e(item.get("label", "reference"))}</a>' for item in references
    )
    if not reference_items:
        reference_items = "No references attached."
    return f"""
<article class="finding {finding.severity}">
  <div class="finding-head">
    <div>
      <div class="badge-row">
        <span class="badge {finding.severity}">{_e(finding.severity)}</span>
        <span class="badge exploit">Exploitability: {_e(finding.exploitability)}</span>
        <span class="badge exploit">Confidence: {_e(finding.confidence or 'medium')}</span>
      </div>
      <h3>{number}. {_e(finding.title)}</h3>
      <p class="muted">{_e(finding.description)}</p>
    </div>
    <div class="rule-id">{_e(finding.rule_id)}</div>
  </div>
  <div class="finding-body">
    <div class="cell">
      <strong>Impact</strong>
      <p>{_e(finding.impact)}</p>
    </div>
    <div class="cell">
      <strong>Evidence</strong>
      <p>{_e(finding.evidence)}</p>
    </div>
    <div class="cell full">
      <strong>Step-by-step Validation Chain</strong>
      <ol>{chain_items}</ol>
    </div>
    <div class="cell">
      <strong>Evidence Quality</strong>
      <p>{_e(finding.evidence_quality or 'Static signal. Validate in runtime context.')}</p>
    </div>
    <div class="cell">
      <strong>Hardening</strong>
      <p>{_e(hardening)}</p>
    </div>
    <div class="cell">
      <strong>Location</strong>
      <p>{_e(finding.location or 'Not tied to a single file entry')}</p>
    </div>
    <div class="cell full">
      <strong>PoC / References</strong>
      <p>{reference_items}</p>
    </div>
  </div>
</article>"""


def _score_card(severity: str, counts: Counter[str]) -> str:
    return (
        f'<div class="score {severity}">'
        f"<strong>{counts.get(severity, 0)}</strong>"
        f"<span>{_e(severity)}</span>"
        "</div>"
    )


def _exploitability_card(label: str, counts: Counter[str]) -> str:
    return (
        '<div class="score">'
        f"<strong>{counts.get(label, 0)}</strong>"
        f"<span>{_e(label)}</span>"
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


def _format_bytes(size: int) -> str:
    units = ["B", "KB", "MB", "GB"]
    value = float(size)
    for unit in units:
        if value < 1024 or unit == units[-1]:
            return f"{value:.1f} {unit}" if unit != "B" else f"{int(value)} B"
        value /= 1024
    return f"{size} B"


def _e(value: str) -> str:
    return html.escape(str(value), quote=True)


def _bool_text(value: bool | None) -> str:
    if value is None:
        return "not declared"
    return "true" if value else "false"
