from __future__ import annotations

from copy import deepcopy

from apk_sentinel.models import Finding

DEFAULT_GUIDANCE = {
    "confidence": "medium",
    "evidence_quality": "Static signal. Validate reachability and data sensitivity before final severity.",
    "exploitation_chain": [
        "Confirm the finding is present in the packaged APK evidence.",
        "Map the affected setting, file, or component to a reachable app behavior.",
        "Exercise that behavior in an authorized lab device or emulator.",
        "Record impact only when the behavior exposes data, changes state, weakens transport, or bypasses an intended boundary.",
    ],
    "references": [
        {"label": "OWASP MASVS", "url": "https://mas.owasp.org/MASVS/"},
        {"label": "OWASP MASTG", "url": "https://mas.owasp.org/MASTG/"},
    ],
}


RULE_GUIDANCE = {
    "parse.warning": {
        "confidence": "low",
        "evidence_quality": "Parser limitation signal. This is assessment hygiene, not a confirmed vulnerability.",
        "exploitation_chain": [
            "Open the APK with a second Android-aware parser such as apktool, aapt2, or jadx.",
            "Compare manifest, resources, certificates, and file inventory against APK Sentinel output.",
            "Treat any missing area as unvalidated until another parser confirms it.",
        ],
        "references": [
            {"label": "OWASP MASTG", "url": "https://mas.owasp.org/MASTG/"},
        ],
    },
    "manifest.debuggable": {
        "confidence": "high",
        "evidence_quality": "Direct manifest evidence from android:debuggable.",
        "exploitation_chain": [
            "Install the exact APK build on an authorized test device or emulator.",
            "Confirm the package is debuggable from the manifest evidence or Android tooling.",
            "Attach a debugger or sanctioned instrumentation session to the running app.",
            "Validate whether runtime secrets, feature flags, client-side checks, or sensitive state can be observed or altered.",
        ],
        "references": [
            {"label": "Android application manifest", "url": "https://developer.android.com/guide/topics/manifest/application-element"},
            {"label": "Android debugging", "url": "https://developer.android.com/studio/debug"},
            {"label": "OWASP MASTG", "url": "https://mas.owasp.org/MASTG/"},
        ],
    },
    "manifest.allow_backup": {
        "confidence": "medium",
        "evidence_quality": "Manifest-backed backup posture. Actual exposure depends on stored data and platform backup rules.",
        "exploitation_chain": [
            "Confirm android:allowBackup or data extraction rules for the build under test.",
            "Inventory local databases, preferences, files, and caches for sensitive values.",
            "Use only an authorized lab backup or restore workflow to validate whether sensitive files are included.",
            "Escalate impact if tokens, private user data, account identifiers, or session material are recoverable.",
        ],
        "references": [
            {"label": "Android app backup", "url": "https://developer.android.com/identity/data/autobackup"},
            {"label": "Android application manifest", "url": "https://developer.android.com/guide/topics/manifest/application-element"},
        ],
    },
    "manifest.cleartext": {
        "confidence": "high",
        "evidence_quality": "Direct manifest evidence that cleartext traffic is allowed by the app.",
        "exploitation_chain": [
            "Route a test device or browser-backed emulator through an authorized proxy.",
            "Exercise login, API, analytics, and content-loading flows while watching for HTTP requests.",
            "If HTTP appears, inspect whether credentials, tokens, identifiers, or state-changing requests are present.",
            "Replay or modify only lab traffic to prove whether responses can influence app behavior.",
        ],
        "references": [
            {"label": "Android network security config", "url": "https://developer.android.com/privacy-and-security/security-config"},
            {"label": "OWASP MASVS Network", "url": "https://mas.owasp.org/MASVS/controls/MASVS-NETWORK/"},
        ],
    },
    "manifest.target_sdk_old": {
        "confidence": "medium",
        "evidence_quality": "Manifest SDK evidence. Exploitability is usually chained with another platform behavior.",
        "exploitation_chain": [
            "Identify compatibility behavior enabled by the target SDK value.",
            "Check whether the app uses permissions, storage, exported components, or background behavior affected by that target.",
            "Validate the behavior on a lab device running a modern Android version.",
            "Treat this as chainable risk unless a concrete behavior produces direct impact.",
        ],
        "references": [
            {"label": "Android behavior changes", "url": "https://developer.android.com/about/versions"},
        ],
    },
    "manifest.min_sdk_legacy": {
        "confidence": "medium",
        "evidence_quality": "Manifest SDK evidence. User exposure depends on supported device population.",
        "exploitation_chain": [
            "Confirm whether production still supports devices below modern Android security baselines.",
            "Identify sensitive flows that rely on platform protections introduced after the minimum SDK.",
            "Validate storage, TLS, and permission behavior on a matching legacy test image if support is real.",
        ],
        "references": [
            {"label": "Android versions", "url": "https://developer.android.com/about/versions"},
        ],
    },
    "manifest.dangerous_permission": {
        "confidence": "medium",
        "evidence_quality": "Manifest permission evidence. Impact depends on whether the permission is granted and reachable.",
        "exploitation_chain": [
            "Map the permission to the feature that requests or uses it.",
            "Confirm whether the permission prompt is justified by a clear user action.",
            "Check exported components, deep links, notifications, or webviews that may trigger the privileged feature.",
            "Escalate only if an attacker-controlled path can use the granted capability or harvest its data.",
        ],
        "references": [
            {"label": "Android permissions", "url": "https://developer.android.com/privacy-and-security/permissions"},
        ],
    },
    "manifest.exported_component": {
        "confidence": "high",
        "evidence_quality": "Manifest-backed externally reachable component without a permission gate.",
        "exploitation_chain": [
            "Identify the exported component name, kind, and package from the manifest evidence.",
            "On an authorized device, invoke the matching component boundary with adb activity-manager or content-provider commands.",
            "Add controlled extras, actions, data URIs, or provider queries that match the component contract.",
            "Confirm impact only if the component leaks data, performs a privileged action, bypasses auth, or crashes reliably from controlled input.",
        ],
        "references": [
            {"label": "PoC reference: adb", "url": "https://developer.android.com/tools/adb"},
            {"label": "Android app components", "url": "https://developer.android.com/guide/components/fundamentals"},
            {"label": "OWASP MASTG", "url": "https://mas.owasp.org/MASTG/"},
        ],
    },
    "manifest.implicit_export": {
        "confidence": "medium",
        "evidence_quality": "Manifest intent-filter evidence. Platform and target SDK decide final reachability.",
        "exploitation_chain": [
            "Identify the component with an intent filter and missing android:exported value.",
            "Confirm how the target Android version treats the component at install and runtime.",
            "Attempt only authorized lab invocation with an intent matching the declared filter.",
            "Escalate if the reachable component exposes internal state or accepts unsafe caller-controlled input.",
        ],
        "references": [
            {"label": "PoC reference: adb", "url": "https://developer.android.com/tools/adb"},
            {"label": "Android app components", "url": "https://developer.android.com/guide/components/fundamentals"},
        ],
    },
    "network.cleartext_config": {
        "confidence": "high",
        "evidence_quality": "Network security config evidence scoped to a base or domain config.",
        "exploitation_chain": [
            "Open the referenced network security config and identify the affected base or domain scope.",
            "Exercise affected flows through an authorized proxy or controlled network.",
            "Capture any HTTP requests carrying credentials, identifiers, personal data, or state changes.",
            "Modify only lab traffic to confirm whether plaintext responses can influence app behavior.",
        ],
        "references": [
            {"label": "Android network security config", "url": "https://developer.android.com/privacy-and-security/security-config"},
            {"label": "OWASP MASVS Network", "url": "https://mas.owasp.org/MASVS/controls/MASVS-NETWORK/"},
        ],
    },
    "network.user_ca_trust": {
        "confidence": "high",
        "evidence_quality": "Network security config evidence that user-installed CAs are trusted.",
        "exploitation_chain": [
            "Install the local testing CA only on a device or browser in scope.",
            "Route the app through the proxy and confirm HTTPS flows decrypt with the user CA.",
            "Inspect whether sensitive API traffic is visible or mutable in the proxy.",
            "Escalate if production domains trust user CAs without a business requirement or compensating controls.",
        ],
        "references": [
            {"label": "Android network security config", "url": "https://developer.android.com/privacy-and-security/security-config"},
            {"label": "OWASP MASVS Network", "url": "https://mas.owasp.org/MASVS/controls/MASVS-NETWORK/"},
        ],
    },
    "files.dynamic_code_asset": {
        "confidence": "medium",
        "evidence_quality": "APK inventory evidence. Runtime loading and integrity controls need dynamic validation.",
        "exploitation_chain": [
            "Locate the packaged DEX, JAR, or APK asset and identify code paths that load it.",
            "Confirm whether the asset is static, downloaded, copied to writable storage, or updated after install.",
            "Validate whether signatures or hashes are checked before loading.",
            "Escalate if attacker-controlled storage, network, or IPC can influence loaded code.",
        ],
        "references": [
            {"label": "OWASP MASTG", "url": "https://mas.owasp.org/MASTG/"},
        ],
    },
    "files.native_libraries": {
        "confidence": "medium",
        "evidence_quality": "APK inventory evidence. Exploitability depends on attacker-controlled input reaching native code.",
        "exploitation_chain": [
            "Inventory native libraries and map them to JNI or framework entry points.",
            "Identify parsers, codecs, crypto, game-engine, or network paths that accept untrusted input.",
            "Run dependency checks and fuzzing on authorized samples where input reaches native code.",
            "Escalate if memory-unsafe code processes attacker-controlled data without modern hardening.",
        ],
        "references": [
            {"label": "OWASP MASTG", "url": "https://mas.owasp.org/MASTG/"},
        ],
    },
    "signing.no_certificate_entry": {
        "confidence": "low",
        "evidence_quality": "ZIP inventory signal only. APK Signature Scheme v2+ may not expose legacy META-INF certificate entries.",
        "exploitation_chain": [
            "Verify signing with Android-aware tooling such as apksigner.",
            "Record certificate lineage and signature scheme versions.",
            "Do not report exploitability unless signing validation fails in the Android verifier.",
        ],
        "references": [
            {"label": "Android app signing", "url": "https://developer.android.com/studio/publish/app-signing"},
        ],
    },
    "assets.secret_indicator": {
        "confidence": "high",
        "evidence_quality": "Direct packaged-file evidence with redacted value preview and proof hash.",
        "exploitation_chain": [
            "Open the referenced APK entry and verify the redacted value plus proof hash.",
            "Identify the owning service or API from surrounding file context.",
            "In an owned test account or service, validate whether the credential is accepted and what restrictions apply.",
            "Rotate and restrict the key immediately if it can authorize real API usage outside the intended app boundary.",
        ],
        "references": [
            {"label": "OWASP MASVS Storage", "url": "https://mas.owasp.org/MASVS/controls/MASVS-STORAGE/"},
            {"label": "Android app security best practices", "url": "https://developer.android.com/privacy-and-security/security-best-practices"},
        ],
    },
}


def enrich_finding(finding: Finding) -> Finding:
    guidance = _guidance_for(finding.rule_id)
    if not finding.confidence:
        finding.confidence = guidance["confidence"]
    if not finding.evidence_quality:
        finding.evidence_quality = guidance["evidence_quality"]
    if not finding.exploitation_chain:
        finding.exploitation_chain = list(guidance["exploitation_chain"])
    if not finding.references:
        finding.references = deepcopy(guidance["references"])
    return finding


def enrich_finding_dict(finding: dict) -> dict:
    enriched = dict(finding)
    guidance = _guidance_for(str(enriched.get("rule_id", "")))
    enriched.setdefault("confidence", guidance["confidence"])
    if not enriched.get("confidence"):
        enriched["confidence"] = guidance["confidence"]
    enriched.setdefault("evidence_quality", guidance["evidence_quality"])
    if not enriched.get("evidence_quality"):
        enriched["evidence_quality"] = guidance["evidence_quality"]
    if not enriched.get("exploitation_chain"):
        enriched["exploitation_chain"] = list(guidance["exploitation_chain"])
    if not enriched.get("references"):
        enriched["references"] = deepcopy(guidance["references"])
    return enriched


def _guidance_for(rule_id: str) -> dict:
    guidance = deepcopy(DEFAULT_GUIDANCE)
    guidance.update(deepcopy(RULE_GUIDANCE.get(rule_id, {})))
    return guidance
