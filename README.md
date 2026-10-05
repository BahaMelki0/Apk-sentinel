# APK Sentinel

Validation / Compare adds optional local apksigner and JADX runs, a bounded local evidence assistant, release comparison, and SARIF export. Finding notes retain confirmed status, reproduction steps, and runtime proof references. Android tools are separate installations; configure `APK_SENTINEL_APKSIGNER` / `APK_SENTINEL_JADX` or add their launchers to PATH. The assistant uses local Ollama and treats static evidence as unverified until a tester confirms it.

APK Sentinel is a local Android APK security assessment framework for authorized mobile testing. It combines static APK analysis, evidence review, a built-in proxy/interceptor, Repeater-style replay, tester notes, case archives, and polished report export into one Flask dashboard.

Its **Obsidian Signal** interface uses graphite surfaces and a shared signal-red accent. Dark mode is the default; the dashboard retains an accessible light-mode toggle.

## V1.1 Highlights

- Dashboard case workflow for uploading APKs, importing local APKs, deleting cases, and exporting/importing full case archives.
- Static findings with severity, exploitability, confidence, evidence quality, validation chains, hardening steps, and references.
- Dependency inventory from Maven metadata, Android SDK properties, native libraries, and framework fingerprints.
- Local vulnerability intelligence cache backed by OSV package/version lookups for discovered Maven dependencies.
- APK content browser with folder-style navigation, safe previews, decoded strings, deep resource search, manifest/component cross-links, and reviewed marks.
- Secrets and indicators page with proof snippets, redaction-friendly context, evidence hashes, and source paths.
- Proxy Lab with local CA generation, HTTP/HTTPS capture, Interceptor, request history, Forward All, and manual Repeater replay with response proof.
- Case notes and per-finding tester notes that flow into HTML report exports.
- Settings page for report author and default proxy host/port, plus About and error pages.

## Quick Start

From this project directory:

```powershell
python -m venv .venv
.\.venv\Scripts\python -m pip install -e .
.\.venv\Scripts\apk-sentinel dashboard --host 127.0.0.1 --port 5050
```

Without installing:

```powershell
$env:PYTHONPATH = "src"
python run_dashboard.py --host 127.0.0.1 --port 5050
```

Open `http://127.0.0.1:5050/`.

## CLI Scan

The CLI is still useful for quick static reports or CI-style checks:

```powershell
$env:PYTHONPATH = "src"
python -m apk_sentinel scan path\to\app.apk --format html --out report.html
python -m apk_sentinel scan path\to\app.apk --format json --fail-on high
python -m apk_sentinel --version
```

## Dashboard Workflow

1. Import an APK from the Dashboard page or restore an exported case archive.
2. Review the case overview, add case notes, and open top findings.
3. Use Findings, Permissions, Components, Intelligence, Secrets & Indicators, and Extracted Content to validate evidence.
4. Mark files as reviewed and add per-finding tester notes such as validation status, false-positive reasoning, or accepted-risk context.
5. Update the OSV cache from Vulnerability Intelligence when network access is available.
6. Use Proxy Lab for runtime traffic capture and Repeater for manual request modification/replay.
7. Build a report with selected findings, proof snippets, vulnerability intelligence, proxy evidence, and tester notes.
8. Export the full case archive when you want to move or preserve the case state.

## Static Intelligence

APK Sentinel treats local heuristic issues as static signals unless the evidence is strong enough to call them findings. Dependency matches from the local vulnerability cache are shown as external vulnerability intelligence and should be validated for reachability before they become confirmed exploit paths.

The current intelligence layer can:

- extract Maven package coordinates from `META-INF/maven/**/pom.properties`;
- fingerprint Android SDK properties, native libraries, and common frameworks;
- update a local OSV cache for Maven package/version matches;
- promote cached vulnerability matches into Findings with MASVS tags and validation chains;
- include dependency and vulnerability evidence in HTML reports.

## Proxy Lab

Proxy Lab is standalone and is not tied to a single APK case. It supports:

- HTTP capture with full request line, headers, body preview, response headers, and response body preview.
- HTTPS decryption when APK Sentinel's local testing CA is trusted by the browser, emulator, or device.
- Interceptor mode that pauses requests until you forward, edit and forward, drop, or Forward All.
- Repeater-style manual replay from captured history or custom raw HTTP requests.
- CA downloads for browser/Brave, PEM tools, Android user CA, and Android system-store workflows.

See [Proxy Setup](docs/PROXY_SETUP.md) for Brave and Android setup notes.

## Storage And Settings

By default the dashboard stores local state in `.apk_sentinel/` under the project directory. You can override the storage path and upload limit before launching:

```powershell
$env:APK_SENTINEL_STORAGE = "C:\path\to\apk-sentinel-store"
$env:APK_SENTINEL_MAX_UPLOAD_MB = "2048"
python run_dashboard.py --host 127.0.0.1 --port 5050
```

The Settings page controls the report author and default proxy host/port for new proxy sessions.

## Documentation

Validation / Compare also links exact URLs in locally decompiled Java/Kotlin to captured requests, retaining source file/line and capture/request identifiers. Refresh after changing artifacts. This bounded heuristic does not establish that a specific source line executed; dynamic URL construction is outside its coverage.

- [Dashboard Guide](docs/DASHBOARD.md)
- [Validation, release comparison and local AI](docs/VALIDATION.md)
- [Proxy Setup](docs/PROXY_SETUP.md)
- [Reporting And Cases](docs/REPORTING_AND_CASES.md)

## Verification

Run `python -m unittest discover -s tests -q`. The October 5 implementation pass passed 14 tests. Browser visual review and real signing/JADX/device checks remain manual release gates; synthetic APK fixtures are parser fixtures, not signed/installable apps.

## Safety Scope

APK Sentinel is built for defensive, authorized mobile application security work. Use it only with APKs, devices, accounts, networks, and traffic you are allowed to assess. The tool stores evidence locally and does not modify APKs or automate exploitation.
