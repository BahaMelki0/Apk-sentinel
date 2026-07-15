# APK Sentinel

APK Sentinel is a local Android APK security assessment framework for authorized mobile testing. It combines static APK analysis, evidence review, a built-in proxy/interceptor, Repeater-style replay, tester notes, case archives, and polished report export into one Flask dashboard.

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

- [Dashboard Guide](docs/DASHBOARD.md)
- [Proxy Setup](docs/PROXY_SETUP.md)
- [Reporting And Cases](docs/REPORTING_AND_CASES.md)

## Safety Scope

APK Sentinel is built for defensive, authorized mobile application security work. Use it only with APKs, devices, accounts, networks, and traffic you are allowed to assess. The tool stores evidence locally and does not modify APKs or automate exploitation.
