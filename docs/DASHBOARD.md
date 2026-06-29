# Dashboard Guide

The APK Sentinel dashboard is the main v1.0 workflow. It is designed to keep the tester close to the evidence: scan output, extracted APK content, proof snippets, proxy captures, notes, and exports all live in the same local case.

## Run The Dashboard

```powershell
$env:PYTHONPATH = "src"
python run_dashboard.py --host 127.0.0.1 --port 5050
```

Open `http://127.0.0.1:5050/`.

## Case Workflow

1. Use Dashboard to upload an APK, analyze an APK already in the project folder, or restore a case archive.
2. Open the case overview and record scope, device, account, and testing notes in Case Notes.
3. Review top findings and jump into Findings for the full report-like list.
4. Use Permissions and Components to validate manifest-driven risks.
5. Use Secrets & Indicators for proof snippets and source locations.
6. Use Extracted Content for filesystem-style APK browsing, decoded strings, manifest previews, resource search, and reviewed marks.
7. Use Dynamic Evidence for case-attached HAR or capture imports, or use standalone Proxy Lab for live traffic work.
8. Build HTML deliverables from Report.
9. Export a full case archive when the case needs to be moved, backed up, or shared inside an authorized engagement.

## Notes

Case notes are stored in `notes.json` beside the case. Per-finding tester notes are tied to a stable finding key generated from rule id, location, and evidence. Notes are included in case archives and report exports.

Good tester notes usually include:

- Validation status.
- Runtime conditions.
- Manual reproduction context.
- False-positive reasoning.
- Accepted-risk justification.
- Links or IDs for external ticketing systems.

## Error Handling

The dashboard has local error pages for missing pages/cases, oversized uploads, and unexpected dashboard failures. Detailed tracebacks still belong in the terminal or process logs, not the browser page.
