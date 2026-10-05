# Validation, release comparison and local assistance

Open **Validation / Compare** after static analysis. Static signals and dependency vulnerability matches require tester validation before being described as confirmed issues.

## Android tools

Install apksigner/JADX separately. Configure `APK_SENTINEL_APKSIGNER` / `APK_SENTINEL_JADX` with launcher paths, or expose them on PATH; restart after environment changes.

Signing checks retain process status and certificate/scheme output. Missing tools report unavailable, not unsigned. JADX writes into `decompiled/` in the case. Runs have a two-minute timeout; partial/failed output is not successful verification. Tools and the selected-finding assistant currently execute synchronously in the request.

## Release comparison and CI

Choose a baseline from the same known package. Comparison reports introduced, removed and changed signals plus permission deltas. Removal is not proof of a runtime fix. Comparison identity uses rule/location; evidence differences remain available.

```powershell
$env:PYTHONPATH = 'src'
python -m apk_sentinel compare before.apk after.apk
python -m apk_sentinel scan app.apk --format sarif --out findings.sarif
python -m apk_sentinel scan app.apk --format json --fail-on high
python -m apk_sentinel verify-signing app.apk
```

SARIF 2.1.0 includes rules, severity and fingerprints; full report context remains in the case.

## Runtime links

Import traffic into the case's **Dynamic Evidence**, then refresh URL links. Standalone Proxy Lab traffic must be attached first. Exact URLs in Java/Kotlin map to captured URLs with file/line and capture/request references.

Limits: 2,000 files, 1 MB per file and 500 matches. No dynamic URL reconstruction or call-path analysis is performed. A match does not prove the displayed source line executed.

## Assistant and reporting

The assistant uses loopback Ollama, default `qwen3.5:9b`, bounded output and a 75-second timeout. It validates the selected finding reference and proposes explanation, steps and limitations. Offline/missing models produce errors. It does not review the entire decompiled codebase or establish exploitability.

Override the local model or address using `APK_SENTINEL_OLLAMA_MODEL` and `APK_SENTINEL_OLLAMA_URL` before launching. The URL must stay loopback.

Record status, reproduction steps and proof references for human validation. Reports include these fields; archives preserve case artifacts. See [reporting](REPORTING_AND_CASES.md).

The October 5 implementation pass passed 14 tests. Live signing/JADX/device checks remain manual because external tools were unavailable on PATH. Synthetic APK ZIP fixtures test parsing only and are not signed/installable apps.
