from __future__ import annotations

import html
from typing import Any, Mapping

"""Shared HTML report chrome for report.py (CLI scan report) and
dashboard.py (per-case report export). Both renderers previously carried
their own ~300-line copy of this CSS and finding-card markup; centralizing
it means a print-layout or styling fix only has to happen once, and the two
reports stay visually consistent."""

BASE_CSS = """
    :root {
      color-scheme: light;
      --page: #f3f5f7;
      --panel: #fff;
      --ink: #18212f;
      --muted: #64707f;
      --line: #d9e0ea;
      --teal: #0f766e;
      --critical: #7f1d1d;
      --high: #b42318;
      --medium: #a16207;
      --low: #1d4ed8;
      --info: #64748b;
    }
    * { box-sizing: border-box; }
    body { margin: 0; background: var(--page); color: var(--ink); font: 14px/1.55 system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
    main { max-width: 1120px; margin: 0 auto; padding: 28px 18px 48px; }
    .hero { border-radius: 8px; padding: 24px; background: #111827; color: #f8fafc; }
    .hero p { color: #cbd5e1; }
    h1, h2, h3, p { margin-top: 0; }
    h1 { margin-bottom: 6px; font-size: 30px; overflow-wrap: anywhere; }
    h2 { margin: 22px 0 12px; font-size: 20px; }
    h3 { margin-bottom: 8px; font-size: 17px; }
    code, pre { max-width: 100%; overflow-wrap: anywhere; word-break: break-word; font-family: ui-monospace, SFMono-Regular, Consolas, "Liberation Mono", monospace; }
    .meta-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 10px; margin-top: 18px; }
    .meta { border: 1px solid rgba(255,255,255,.16); border-radius: 8px; padding: 12px; background: rgba(255,255,255,.07); }
    .meta span { display: block; color: #bfdbfe; font-size: 11px; font-weight: 800; letter-spacing: .06em; text-transform: uppercase; }
    .meta strong { display: block; margin-top: 5px; overflow-wrap: anywhere; }
    .panel, .finding { border: 1px solid var(--line); border-radius: 8px; background: var(--panel); }
    .panel { margin-top: 16px; padding: 18px; }
    .finding { margin-top: 12px; overflow: hidden; border-left: 7px solid var(--info); }
    .finding.critical { border-left-color: var(--critical); }
    .finding.high { border-left-color: var(--high); }
    .finding.medium { border-left-color: var(--medium); }
    .finding.low { border-left-color: var(--low); }
    .finding.info { border-left-color: var(--info); }
    .finding-head { display: flex; justify-content: space-between; gap: 14px; padding: 16px; border-bottom: 1px solid var(--line); background: #fbfcfe; }
    .finding-body { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); }
    .cell { min-width: 0; padding: 14px 16px; border-bottom: 1px solid var(--line); }
    .cell:nth-child(odd) { border-right: 1px solid var(--line); }
    .cell.full { grid-column: 1 / -1; border-right: 0; }
    .cell strong { display: block; margin-bottom: 6px; color: #334155; font-size: 11px; font-weight: 850; letter-spacing: .07em; text-transform: uppercase; }
    .badge-row { display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 10px; }
    .badge { display: inline-flex; align-items: center; min-height: 24px; border-radius: 999px; padding: 3px 8px; color: #fff; font-size: 11px; font-weight: 850; text-transform: uppercase; }
    .badge.critical { background: var(--critical); }
    .badge.high { background: var(--high); }
    .badge.medium { background: var(--medium); }
    .badge.low { background: var(--low); }
    .badge.info { background: var(--info); }
    .badge.neutral { background: var(--teal); }
    .chain { margin: 0; padding-left: 20px; }
    .chain li { margin-bottom: 6px; }
    .proof { display: block; width: 100%; max-width: 100%; max-height: 320px; margin: 0; overflow: auto; border: 1px solid var(--line); border-left: 5px solid var(--low); border-radius: 8px; padding: 12px; background: #f8fafc; color: #111827; white-space: pre-wrap; overflow-wrap: anywhere; word-break: break-word; }
    .evidence-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 12px; }
    .evidence-card { min-width: 0; border: 1px solid var(--line); border-left: 6px solid var(--low); border-radius: 8px; background: #fff; overflow: hidden; }
    .evidence-card.critical { border-left-color: var(--critical); }
    .evidence-card.high { border-left-color: var(--high); }
    .evidence-card.medium { border-left-color: var(--medium); }
    .evidence-card.low { border-left-color: var(--low); }
    .evidence-head { padding: 12px; border-bottom: 1px solid var(--line); background: #fbfcfe; }
    .evidence-head h3 { margin-bottom: 4px; overflow-wrap: anywhere; }
    .evidence-meta { display: grid; gap: 8px; padding: 12px; }
    .evidence-meta div { min-width: 0; }
    .evidence-meta strong { display: block; margin-bottom: 3px; color: #334155; font-size: 11px; font-weight: 850; letter-spacing: .07em; text-transform: uppercase; }
    table { width: 100%; max-width: 100%; border-collapse: collapse; table-layout: fixed; }
    th, td { min-width: 0; border-bottom: 1px solid var(--line); padding: 9px; text-align: left; vertical-align: top; overflow-wrap: anywhere; word-break: break-word; }
    th { color: #334155; font-size: 11px; letter-spacing: .06em; text-transform: uppercase; }
    .proxy-table th:nth-child(1) { width: 82px; }
    .proxy-table th:nth-child(4) { width: 82px; }
    a { color: #0f766e; }
    .muted { color: var(--muted); }
    .empty { border: 1px dashed var(--line); border-radius: 8px; padding: 18px; color: var(--muted); background: #f8fafc; }
    .report-toolbar { display: flex; justify-content: flex-end; gap: 10px; margin-bottom: 12px; }
    .report-toolbar button { border: 1px solid var(--line); border-radius: 6px; background: #fff; color: var(--ink); font: inherit; font-weight: 650; padding: 8px 14px; cursor: pointer; }
    .report-toolbar button:hover { background: #f1f5f9; }
    @media (max-width: 760px) {
      .finding-head, .finding-body { display: block; }
      .cell, .cell:nth-child(odd) { border-right: 0; }
    }
    /* Print / Save-as-PDF layout. Browsers default to dropping backgrounds and
       ignoring page-break hints, so the hero previously printed as a solid
       black rectangle and findings could split mid-card across pages. */
    @media print {
      .report-toolbar { display: none !important; }
      body { background: #fff; }
      main { max-width: none; padding: 0; }
      .hero {
        background: #111827 !important;
        color: #f8fafc !important;
        -webkit-print-color-adjust: exact;
        print-color-adjust: exact;
        break-inside: avoid;
      }
      .badge {
        -webkit-print-color-adjust: exact;
        print-color-adjust: exact;
      }
      section, .panel, .finding, .evidence-card { break-inside: avoid; }
      h2 { break-after: avoid; break-inside: avoid; }
      a { color: inherit; text-decoration: underline; }
      a[href]::after { content: " (" attr(href) ")"; font-size: 10px; color: var(--muted); }
      @page { margin: 14mm 12mm; }
    }
"""


def escape(value: Any) -> str:
    return html.escape(str(value if value is not None else ""), quote=True)


def finding_card_html(finding: Mapping[str, Any], number: int) -> str:
    """Render one finding card. `finding` may be any mapping (a dict, or a
    dataclasses.asdict()'d Finding) with the standard finding fields."""
    severity = finding.get("severity") or "info"
    exploitability = finding.get("exploitability") or "needs validation"
    confidence = finding.get("confidence") or "medium"
    chain = finding.get("exploitation_chain") or [finding.get("attack_path", "Validate in context.")]
    chain_items = "\n".join(f"<li>{escape(step)}</li>" for step in chain)
    references = finding.get("references") or []
    reference_items = " ".join(
        f'<a href="{escape(item.get("url", ""))}">{escape(item.get("label", "reference"))}</a>' for item in references
    )
    if not reference_items:
        reference_items = "No references attached."
    hardening = finding.get("hardening") or finding.get("recommendation") or ""

    extra_cells = ""
    if finding.get("tester_status") is not None or finding.get("tester_notes") is not None:
        extra_cells = (
            f'<div class="cell"><strong>Tester Status</strong><p>{escape(finding.get("tester_status", "open"))}</p></div>'
            f'<div class="cell"><strong>Tester Notes</strong><p>{escape(finding.get("tester_notes") or "No tester note recorded.")}</p></div>'
        )
    else:
        extra_cells = (
            f'<div class="cell"><strong>Hardening</strong><p>{escape(hardening)}</p></div>'
            f'<div class="cell"><strong>Location</strong><p>{escape(finding.get("location") or "Not tied to a single file entry")}</p></div>'
        )

    return f"""
<article class="finding {escape(severity)}">
  <div class="finding-head">
    <div>
      <div class="badge-row">
        <span class="badge {escape(severity)}">{escape(severity)}</span>
        <span class="badge neutral">Exploitability: {escape(exploitability)}</span>
        <span class="badge neutral">Confidence: {escape(confidence)}</span>
      </div>
      <h3>{number}. {escape(finding.get("title", "Untitled finding"))}</h3>
      <p class="muted">{escape(finding.get("description", ""))}</p>
    </div>
    <code>{escape(finding.get("rule_id", ""))}</code>
  </div>
  <div class="finding-body">
    <div class="cell"><strong>Impact</strong><p>{escape(finding.get("impact", ""))}</p></div>
    <div class="cell"><strong>Evidence</strong><p>{escape(finding.get("evidence", ""))}</p></div>
    <div class="cell full"><strong>Step-by-step Validation Chain</strong><ol class="chain">{chain_items}</ol></div>
    <div class="cell"><strong>Evidence Quality</strong><p>{escape(finding.get("evidence_quality", "") or "Static signal. Validate in runtime context.")}</p></div>
    {extra_cells}
    <div class="cell full"><strong>PoC / References</strong><p>{reference_items}</p></div>
  </div>
</article>"""


def format_bytes(size: int) -> str:
    units = ["B", "KB", "MB", "GB"]
    value = float(size)
    for unit in units:
        if value < 1024 or unit == units[-1]:
            return f"{value:.1f} {unit}" if unit != "B" else f"{int(value)} B"
        value /= 1024
    return f"{size} B"


REPORT_TOOLBAR_HTML = """
  <div class="report-toolbar">
    <button type="button" onclick="window.print()">Save as PDF / Print</button>
  </div>
"""
