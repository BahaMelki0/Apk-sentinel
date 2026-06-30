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
5. Use Intelligence to review dependency inventory and cached vulnerability matches.
6. Use Secrets & Indicators for proof snippets and source locations.
7. Use Extracted Content for filesystem-style APK browsing, decoded strings, manifest previews, resource search, and reviewed marks.
8. Use Dynamic Evidence for case-attached HAR or capture imports, or use standalone Proxy Lab for live traffic work.
9. Build HTML deliverables from Report.
10. Export a full case archive when the case needs to be moved, backed up, or shared inside an authorized engagement.

## Static Intelligence

The Intelligence pages separate local static signals from external vulnerability matches. APK Sentinel extracts package evidence from Maven metadata, Android SDK properties, native library inventory, and common framework fingerprints. Maven package/version entries can be queried against OSV and cached locally.

External vulnerability matches are promoted into Findings as `external vuln match`, but they still need reachability validation before a tester calls them exploitable.

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
