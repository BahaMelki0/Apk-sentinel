from __future__ import annotations

from dataclasses import dataclass, field

SEVERITY_ORDER = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


@dataclass
class FileEntry:
    name: str
    compressed_size: int
    uncompressed_size: int


@dataclass
class AppComponent:
    kind: str
    name: str | None
    exported: bool | None
    permission: str | None
    intent_filters: int = 0


@dataclass
class NetworkSecurityConfig:
    path: str
    cleartext_traffic_permitted: list[dict[str, str]] = field(default_factory=list)
    trust_anchors: list[str] = field(default_factory=list)


@dataclass
class ApkProfile:
    path: str
    file_name: str
    size_bytes: int
    sha256: str
    package_name: str | None = None
    version_code: str | None = None
    version_name: str | None = None
    min_sdk: int | None = None
    target_sdk: int | None = None
    permissions: list[str] = field(default_factory=list)
    application_attrs: dict[str, str] = field(default_factory=dict)
    components: list[AppComponent] = field(default_factory=list)
    network_security_config: NetworkSecurityConfig | None = None
    files: list[FileEntry] = field(default_factory=list)
    certificates: list[str] = field(default_factory=list)
    dex_files: list[str] = field(default_factory=list)
    native_libraries: list[str] = field(default_factory=list)
    asset_entries: list[str] = field(default_factory=list)
    dependencies: list[dict[str, str]] = field(default_factory=list)
    secret_indicators: list[dict[str, str]] = field(default_factory=list)
    parse_warnings: list[str] = field(default_factory=list)


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    description: str
    evidence: str
    recommendation: str
    exploitability: str = "needs validation"
    impact: str = "Requires analyst validation in the app's production context."
    attack_path: str = "Validate the finding against the app's reachable behavior and data sensitivity."
    hardening: str = ""
    location: str | None = None
    confidence: str = ""
    evidence_quality: str = ""
    exploitation_chain: list[str] = field(default_factory=list)
    references: list[dict[str, str]] = field(default_factory=list)
    finding_type: str = ""
    masvs: list[str] = field(default_factory=list)


@dataclass
class ScanResult:
    profile: ApkProfile
    findings: list[Finding]

    def has_severity_at_or_above(self, severity: str) -> bool:
        threshold = SEVERITY_ORDER[severity]
        return any(SEVERITY_ORDER[finding.severity] >= threshold for finding in self.findings)
