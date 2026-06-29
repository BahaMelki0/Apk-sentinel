from __future__ import annotations

from apk_sentinel.finding_guidance import enrich_finding
from apk_sentinel.models import ApkProfile, Finding

DANGEROUS_PERMISSIONS = {
    "android.permission.ACCEPT_HANDOVER": "phone call handover",
    "android.permission.ACCESS_BACKGROUND_LOCATION": "background location",
    "android.permission.ACCESS_COARSE_LOCATION": "coarse location",
    "android.permission.ACCESS_FINE_LOCATION": "precise location",
    "android.permission.BLUETOOTH_CONNECT": "Bluetooth device access",
    "android.permission.BODY_SENSORS": "body sensor data",
    "android.permission.CALL_PHONE": "placing phone calls",
    "android.permission.CAMERA": "camera access",
    "android.permission.GET_ACCOUNTS": "account access",
    "android.permission.POST_NOTIFICATIONS": "notification access",
    "android.permission.READ_CALENDAR": "calendar reads",
    "android.permission.READ_CALL_LOG": "call log reads",
    "android.permission.READ_CONTACTS": "contact reads",
    "android.permission.READ_EXTERNAL_STORAGE": "external storage reads",
    "android.permission.READ_MEDIA_AUDIO": "audio media reads",
    "android.permission.READ_MEDIA_IMAGES": "image media reads",
    "android.permission.READ_MEDIA_VIDEO": "video media reads",
    "android.permission.READ_PHONE_NUMBERS": "phone number reads",
    "android.permission.READ_PHONE_STATE": "phone state reads",
    "android.permission.READ_SMS": "SMS reads",
    "android.permission.RECEIVE_MMS": "MMS receives",
    "android.permission.RECEIVE_SMS": "SMS receives",
    "android.permission.RECORD_AUDIO": "microphone access",
    "android.permission.SEND_SMS": "SMS sends",
    "android.permission.WRITE_CALENDAR": "calendar writes",
    "android.permission.WRITE_CALL_LOG": "call log writes",
    "android.permission.WRITE_CONTACTS": "contact writes",
    "android.permission.WRITE_EXTERNAL_STORAGE": "external storage writes",
}


def evaluate_rules(profile: ApkProfile) -> list[Finding]:
    findings: list[Finding] = []
    findings.extend(_parse_warning_findings(profile))
    findings.extend(_application_findings(profile))
    findings.extend(_permission_findings(profile))
    findings.extend(_component_findings(profile))
    findings.extend(_network_findings(profile))
    findings.extend(_file_inventory_findings(profile))
    findings.extend(_secret_findings(profile))
    return [enrich_finding(finding) for finding in findings]


def _parse_warning_findings(profile: ApkProfile) -> list[Finding]:
    return [
        Finding(
            rule_id="parse.warning",
            title="APK parsing warning",
            severity="low",
            description="Some APK metadata could not be parsed.",
            evidence=warning,
            recommendation="Inspect the APK with apktool, aapt2, or jadx to confirm the missing metadata.",
            exploitability="low",
            impact="The scanner may have incomplete visibility, so other manifest-based risks could be missed.",
            attack_path="This is not directly exploitable by itself; it means the assessment should be treated as incomplete until a second parser confirms the missing metadata.",
            hardening="Re-run with apktool, aapt2, or jadx output and add the failed sample to the parser regression suite.",
        )
        for warning in profile.parse_warnings
    ]


def _application_findings(profile: ApkProfile) -> list[Finding]:
    findings: list[Finding] = []
    app = profile.application_attrs

    if _is_true(app.get("android:debuggable")):
        findings.append(
            Finding(
                rule_id="manifest.debuggable",
                title="Application is debuggable",
                severity="high",
                description="Debuggable builds can expose runtime internals and weaken production hardening.",
                evidence="android:debuggable=true",
                recommendation="Set android:debuggable to false for release builds.",
                exploitability="high",
                impact="A production debuggable app can expose runtime state, sensitive values, and control flow to anyone with a test device or instrumented environment.",
                attack_path="An attacker with device-level access can attach debugging or instrumentation to observe secrets, alter branches, and bypass client-side checks during runtime analysis.",
                hardening="Disable android:debuggable in release variants, enforce release signing in CI, and fail builds that ship debug flags.",
                location="AndroidManifest.xml application",
            )
        )

    allow_backup = app.get("android:allowBackup")
    if allow_backup is None or _is_true(allow_backup):
        findings.append(
            Finding(
                rule_id="manifest.allow_backup",
                title="Application backup is enabled or implicit",
                severity="medium",
                description="Android backup can expose app data through device backup channels when not explicitly controlled.",
                evidence=f"android:allowBackup={allow_backup or '(not declared; platform default may apply)'}",
                recommendation="Declare android:allowBackup=false or define precise backup rules for sensitive apps.",
                exploitability="medium",
                impact="Sensitive local data may be copied into backup or restore flows if backup rules are broad.",
                attack_path="If the app stores tokens, identifiers, or private user data locally, a backup-capable environment can preserve and inspect that data outside normal app access controls.",
                hardening="Set android:allowBackup=false for sensitive apps, or define dataExtractionRules/fullBackupContent that excludes secrets, caches, tokens, and private databases.",
                location="AndroidManifest.xml application",
            )
        )

    if _is_true(app.get("android:usesCleartextTraffic")):
        findings.append(
            Finding(
                rule_id="manifest.cleartext",
                title="Cleartext traffic is enabled",
                severity="high",
                description="Plain HTTP traffic can expose sensitive data to network observers or manipulation.",
                evidence="android:usesCleartextTraffic=true",
                recommendation="Require HTTPS and disable cleartext traffic unless a narrowly scoped exception is needed.",
                exploitability="high",
                impact="Traffic sent over HTTP can be read or modified by a network-positioned attacker.",
                attack_path="When any endpoint falls back to HTTP, a hostile Wi-Fi, proxy, or compromised network path can observe requests and inject modified responses into the app session.",
                hardening="Set android:usesCleartextTraffic=false, move endpoints to HTTPS, and keep any debug-only HTTP exceptions scoped in network security config.",
                location="AndroidManifest.xml application",
            )
        )

    if profile.target_sdk is not None and profile.target_sdk < 31:
        findings.append(
            Finding(
                rule_id="manifest.target_sdk_old",
                title="Target SDK is below Android 12",
                severity="medium",
                description="Older target SDKs miss newer platform security requirements and compatibility behavior.",
                evidence=f"targetSdkVersion={profile.target_sdk}",
                recommendation="Raise targetSdkVersion to a currently supported Android API level after compatibility testing.",
                exploitability="medium",
                impact="The app may run under legacy compatibility behavior that weakens platform-enforced security expectations.",
                attack_path="Attackers usually chain this with another issue, taking advantage of older permission, component, storage, or background-execution behavior that newer target SDKs restrict.",
                hardening="Raise targetSdkVersion, test behavior changes, and use CI policy to keep target SDK current with Play and Android platform requirements.",
                location="AndroidManifest.xml uses-sdk",
            )
        )

    if profile.min_sdk is not None and profile.min_sdk < 23:
        findings.append(
            Finding(
                rule_id="manifest.min_sdk_legacy",
                title="Minimum SDK supports legacy Android versions",
                severity="low",
                description="Very old Android versions lack modern permission and platform security controls.",
                evidence=f"minSdkVersion={profile.min_sdk}",
                recommendation="Evaluate whether legacy OS support is still required for the app's threat model.",
                exploitability="low",
                impact="Users on legacy Android versions receive weaker platform protection for permissions, storage, TLS, and process isolation.",
                attack_path="This becomes relevant when the app handles sensitive data on old devices where platform mitigations are missing or inconsistent.",
                hardening="Raise minSdkVersion when product requirements allow, or add explicit app-side safeguards for storage, transport security, and permissions on legacy devices.",
                location="AndroidManifest.xml uses-sdk",
            )
        )

    return findings


def _permission_findings(profile: ApkProfile) -> list[Finding]:
    findings: list[Finding] = []
    for permission in profile.permissions:
        if permission in DANGEROUS_PERMISSIONS:
            findings.append(
                Finding(
                    rule_id="manifest.dangerous_permission",
                    title="Dangerous permission requested",
                    severity="medium",
                    description="Dangerous permissions expose sensitive user data or privileged device capabilities.",
                    evidence=f"{permission} grants {DANGEROUS_PERMISSIONS[permission]}",
                    recommendation="Confirm the permission is necessary and gated by clear user-facing behavior.",
                    exploitability="contextual",
                    impact="If granted, the permission gives the app access to sensitive user data or device capabilities.",
                    attack_path="The permission is exploitable when another weakness lets an attacker trigger the privileged feature, abuse collected data, or trick the user into granting access without clear need.",
                    hardening="Remove unused permissions, request access just in time, explain the user-visible need, and gate sensitive flows with server-side and local authorization checks.",
                    location="AndroidManifest.xml uses-permission",
                )
            )
    return findings


def _component_findings(profile: ApkProfile) -> list[Finding]:
    findings: list[Finding] = []
    for component in profile.components:
        name = component.name or "(anonymous)"
        location = f"AndroidManifest.xml {component.kind} {name}"
        if component.exported is True and not component.permission:
            findings.append(
                Finding(
                    rule_id="manifest.exported_component",
                    title="Exported component lacks a permission gate",
                    severity="high",
                    description="Exported Android components can be invoked by other apps unless guarded by permissions or strict validation.",
                    evidence=f"{component.kind} {name} exported=true permission=(none)",
                    recommendation="Set exported=false where possible, or require a signature-level permission and validate all inputs.",
                    exploitability="high",
                    impact="Other apps can reach this component boundary directly, which may expose internal actions, deep links, content, or broadcast handling.",
                    attack_path="A separate app on the same device can send intents, content-provider requests, or broadcasts to the exported component and exercise code paths that were intended for trusted callers.",
                    hardening="Set android:exported=false unless external access is required, add signature-level permissions for trusted integrations, and validate every intent extra, URI, caller, and state transition.",
                    location=location,
                )
            )
        elif component.exported is None and component.intent_filters:
            findings.append(
                Finding(
                    rule_id="manifest.implicit_export",
                    title="Component export behavior is implicit",
                    severity="medium",
                    description="Intent filters can make components externally reachable on older targets, and implicit export state is easy to misread.",
                    evidence=f"{component.kind} {name} has {component.intent_filters} intent-filter(s) and no android:exported value",
                    recommendation="Declare android:exported explicitly and restrict externally reachable entry points.",
                    exploitability="medium",
                    impact="The component may be externally reachable depending on platform behavior and target SDK.",
                    attack_path="Another app can potentially match the declared intent filter and reach the component if the platform treats it as exported.",
                    hardening="Declare android:exported explicitly, keep externally reachable intent filters minimal, and validate caller-controlled data.",
                    location=location,
                )
            )
    return findings


def _network_findings(profile: ApkProfile) -> list[Finding]:
    findings: list[Finding] = []
    config = profile.network_security_config
    if not config:
        return findings

    for entry in config.cleartext_traffic_permitted:
        if _is_true(entry["value"]):
            findings.append(
                Finding(
                    rule_id="network.cleartext_config",
                    title="Network security config allows cleartext traffic",
                    severity="high",
                    description="The network security config permits plaintext HTTP traffic for at least one scope.",
                    evidence=f"{entry['tag']} cleartextTrafficPermitted=true",
                    recommendation="Disable cleartext traffic or restrict it to non-sensitive debug-only endpoints.",
                    exploitability="high",
                    impact="HTTP traffic allowed by network security config can expose or modify app traffic within that scope.",
                    attack_path="A network-positioned attacker can observe or tamper with allowed cleartext requests if the affected domain carries sensitive data or state-changing operations.",
                    hardening="Set cleartextTrafficPermitted=false by default, scope exceptions to non-sensitive debug hosts, and verify production endpoints use HTTPS only.",
                    location=config.path,
                )
            )

    if "user" in config.trust_anchors:
        findings.append(
            Finding(
                rule_id="network.user_ca_trust",
                title="Network security config trusts user CAs",
                severity="medium",
                description="Trusting user-installed CAs can make TLS interception easier on compromised or managed devices.",
                evidence="certificates src=user",
                recommendation="Use system trust anchors in production unless user CA trust is a deliberate enterprise requirement.",
                exploitability="medium",
                impact="TLS interception is easier when user-installed certificate authorities are trusted for production traffic.",
                attack_path="If a user CA is installed on the device, traffic can be intercepted by infrastructure that presents certificates chaining to that CA.",
                hardening="Trust system CAs for production domains, reserve user CA trust for debug or enterprise builds, and consider certificate pinning for high-risk APIs.",
                location=config.path,
            )
        )

    return findings


def _file_inventory_findings(profile: ApkProfile) -> list[Finding]:
    findings: list[Finding] = []
    nested_code = [
        name
        for name in profile.asset_entries
        if name.endswith((".dex", ".jar", ".apk")) or "/dex/" in name.lower()
    ]
    for name in nested_code:
        findings.append(
            Finding(
                rule_id="files.dynamic_code_asset",
                title="Executable code is packaged as an asset",
                severity="medium",
                description="Nested DEX, JAR, or APK assets can indicate plugin systems, dynamic loading, or hidden execution paths.",
                evidence=name,
                recommendation="Confirm dynamic code loading is intended, integrity-checked, and covered by code review.",
                exploitability="medium",
                impact="Dynamically loaded code can expand the executable surface beyond the main DEX files and complicate review.",
                attack_path="If the app loads this asset or updates it from storage/network without strong integrity checks, an attacker who can influence that path may alter code executed by the app.",
                hardening="Avoid dynamic loading where possible, verify signatures or hashes before loading, store code in protected locations, and include nested code in static review.",
                location=name,
            )
        )

    if profile.native_libraries:
        findings.append(
            Finding(
                rule_id="files.native_libraries",
                title="APK contains native libraries",
                severity="info",
                description="Native code can contain memory safety issues and may require separate review tooling.",
                evidence=f"{len(profile.native_libraries)} native library file(s) found",
                recommendation="Run native library scanning, symbol review, and dependency checks for bundled .so files.",
                exploitability="contextual",
                impact="Native libraries may contain memory-corruption bugs, unsafe JNI boundaries, or outdated third-party dependencies.",
                attack_path="Exploitability depends on whether attacker-controlled input reaches native parsing, media, networking, crypto, or game-engine code paths.",
                hardening="Inventory native dependencies, strip accidental debug symbols, enable compiler hardening, and fuzz JNI/native parsers that handle untrusted input.",
            )
        )

    if not profile.certificates:
        findings.append(
            Finding(
                rule_id="signing.no_certificate_entry",
                title="No signing certificate entry found",
                severity="low",
                description="The APK did not expose common META-INF signing certificate files in the ZIP inventory.",
                evidence="No META-INF/*.RSA, *.DSA, *.EC, or *.SF entries found",
                recommendation="Verify signing status with apksigner or jarsigner.",
                exploitability="low",
                impact="Signing state could not be confirmed from ZIP inventory alone.",
                attack_path="This is not directly exploitable as reported; it is a signal to verify APK signature schemes with Android-aware tooling.",
                hardening="Validate APK signing with apksigner and record certificate lineage in release checks.",
            )
        )

    return findings


def _secret_findings(profile: ApkProfile) -> list[Finding]:
    findings: list[Finding] = []
    for indicator in profile.secret_indicators:
        findings.append(
            Finding(
                rule_id="assets.secret_indicator",
                title="Potential secret found in packaged asset",
                severity="high",
                description="Packaged assets are visible to anyone who can inspect the APK.",
                evidence=f"{indicator['kind']} pattern in {indicator['path']}",
                recommendation="Remove secrets from client packages and rotate exposed credentials.",
                exploitability="high",
                impact="A credential or API key packaged in the APK can be extracted and reused outside the intended client.",
                attack_path="Anyone with the APK can inspect packaged assets and recover embedded keys, then attempt to use them against the related backend or third-party service.",
                hardening="Remove client-side secrets, rotate exposed keys, restrict API keys by package name/signing certificate and backend policy, and move privileged operations server-side.",
                location=indicator["path"],
            )
        )
    return findings


def _is_true(value: str | None) -> bool:
    return bool(value and value.lower() == "true")
