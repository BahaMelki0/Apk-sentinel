# Reporting And Cases

APK Sentinel cases are local folders under the configured storage path. A case includes scan metadata, findings, file inventory, extracted indicators, dynamic evidence, review marks, tester notes, and the uploaded APK copy.

## Case Archive

Use Export Case from the case overview to create a ZIP containing the full case state. Use Import Case Archive from the Dashboard page to restore it.

Archives are intended for authorized engagement handoff and backup. They can contain APK bytes, proof snippets, hostnames, request data, tester notes, and other sensitive evidence.

## Report Builder

The Report page exports polished HTML. Reports can include:

- Selected findings.
- Exploitability, confidence, evidence quality, attack path, hardening, and references.
- MASVS tags and finding type, such as static signal or external vuln match.
- Case notes and per-finding tester notes.
- Secrets and indicator proof snippets.
- Dependency inventory and cached vulnerability intelligence.
- Proxy capture summaries and replay evidence.
- Tester name from Settings or the report form.

## Finding Notes

Each finding has a tester note area with status:

- `open`
- `reviewed`
- `confirmed`
- `accepted risk`
- `false positive`

Use this to separate scanner output from human validation. The finding may still exist in the scan, but the report will show the tester's status and notes.

Record reproduction steps and a runtime proof reference alongside the status. These fields persist and appear in HTML exports. Confirmed status is a tester decision, not an automatic conclusion from static scanning or local AI.

Validation tool output and URL evidence links are retained in `tool_assessment.json`; JADX source resides in the case's `decompiled/` directory. Full archives may therefore grow substantially and contain additional private source/traffic evidence. See [validation workflow](VALIDATION.md) for comparison, SARIF and runtime-link limits.

## Suggested V1.0 Report Flow

1. Add case notes with scope, test device, test account, and limitations.
2. Review each high-impact finding.
3. Add per-finding notes for validated issues and false positives.
4. Select only the findings you want in the final report.
5. Include indicators, vulnerability intelligence, and proxy proof when they strengthen the evidence.
6. Export HTML for review and delivery.
7. Export the case archive for reproducibility.
