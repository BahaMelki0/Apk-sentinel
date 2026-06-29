# Reporting And Cases

APK Sentinel cases are local folders under the configured storage path. A case includes scan metadata, findings, file inventory, extracted indicators, dynamic evidence, review marks, tester notes, and the uploaded APK copy.

## Case Archive

Use Export Case from the case overview to create a ZIP containing the full case state. Use Import Case Archive from the Dashboard page to restore it.

Archives are intended for authorized engagement handoff and backup. They can contain APK bytes, proof snippets, hostnames, request data, tester notes, and other sensitive evidence.

## Report Builder

The Report page exports polished HTML. Reports can include:

- Selected findings.
- Exploitability, confidence, evidence quality, attack path, hardening, and references.
- Case notes and per-finding tester notes.
- Secrets and indicator proof snippets.
- Proxy capture summaries and replay evidence.
- Tester name from Settings or the report form.

## Finding Notes

Each finding has a tester note area with status:

- `open`
- `reviewed`
- `accepted risk`
- `false positive`

Use this to separate scanner output from human validation. The finding may still exist in the scan, but the report will show the tester's status and notes.

## Suggested V1.0 Report Flow

1. Add case notes with scope, test device, test account, and limitations.
2. Review each high-impact finding.
3. Add per-finding notes for validated issues and false positives.
4. Select only the findings you want in the final report.
5. Include indicators and proxy proof when they strengthen the evidence.
6. Export HTML for review and delivery.
7. Export the case archive for reproducibility.
