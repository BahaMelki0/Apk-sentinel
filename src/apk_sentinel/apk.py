from __future__ import annotations

import hashlib
import re
import zipfile
from pathlib import Path

from apk_sentinel.axml import AxmlParseError, parse_xml_bytes
from apk_sentinel.manifest import parse_manifest_tree
from apk_sentinel.models import ApkProfile, FileEntry, NetworkSecurityConfig

TEXT_SCAN_EXTENSIONS = {
    ".json",
    ".txt",
    ".xml",
    ".properties",
    ".conf",
    ".config",
    ".ini",
    ".pem",
    ".key",
    ".cer",
    ".crt",
}

SECRET_PATTERNS = {
    "aws_access_key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "google_api_key": re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
    "private_key": re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
    "slack_token": re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"),
}


def read_apk(path: Path) -> ApkProfile:
    apk_path = path.resolve()
    if not apk_path.exists():
        raise FileNotFoundError(apk_path)
    if not zipfile.is_zipfile(apk_path):
        raise ValueError(f"{apk_path} is not a valid APK/ZIP file")

    profile = ApkProfile(
        path=str(apk_path),
        file_name=apk_path.name,
        size_bytes=apk_path.stat().st_size,
        sha256=_sha256(apk_path),
    )

    with zipfile.ZipFile(apk_path) as archive:
        names = archive.namelist()
        profile.files = [_entry(info) for info in archive.infolist()]
        profile.dex_files = sorted(name for name in names if re.fullmatch(r"classes(\d*)\.dex", name))
        profile.native_libraries = sorted(name for name in names if name.startswith("lib/") and name.endswith(".so"))
        profile.certificates = sorted(
            name
            for name in names
            if name.upper().startswith("META-INF/")
            and name.upper().endswith((".RSA", ".DSA", ".EC", ".SF"))
        )
        profile.asset_entries = sorted(name for name in names if name.startswith(("assets/", "res/raw/")))

        manifest_error = _load_manifest(profile, archive, names)
        if manifest_error:
            profile.parse_warnings.append(manifest_error)

        _load_network_security_config(profile, archive, names)
        _scan_text_assets(profile, archive)

    return profile


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _entry(info: zipfile.ZipInfo) -> FileEntry:
    return FileEntry(
        name=info.filename,
        compressed_size=info.compress_size,
        uncompressed_size=info.file_size,
    )


def _load_manifest(profile: ApkProfile, archive: zipfile.ZipFile, names: list[str]) -> str | None:
    if "AndroidManifest.xml" not in names:
        return "AndroidManifest.xml was not found"

    data = archive.read("AndroidManifest.xml")
    try:
        root = parse_xml_bytes(data)
    except AxmlParseError as exc:
        return f"AndroidManifest.xml could not be parsed: {exc}"

    manifest = parse_manifest_tree(root)
    profile.package_name = manifest.package_name
    profile.version_code = manifest.version_code
    profile.version_name = manifest.version_name
    profile.min_sdk = manifest.min_sdk
    profile.target_sdk = manifest.target_sdk
    profile.permissions = manifest.permissions
    profile.application_attrs = manifest.application_attrs
    profile.components = manifest.components
    return None


def _load_network_security_config(profile: ApkProfile, archive: zipfile.ZipFile, names: list[str]) -> None:
    candidates = [
        "res/xml/network_security_config.xml",
        "res/xml/network-security-config.xml",
    ]
    app_config = profile.application_attrs.get("android:networkSecurityConfig")
    if app_config and app_config.startswith("@xml/"):
        resource_name = app_config.removeprefix("@xml/")
        candidates.insert(0, f"res/xml/{resource_name}.xml")

    for name in candidates:
        if name not in names:
            continue
        try:
            root = parse_xml_bytes(archive.read(name))
        except AxmlParseError as exc:
            profile.parse_warnings.append(f"{name} could not be parsed: {exc}")
            return
        profile.network_security_config = _parse_network_security_config(name, root)
        return


def _parse_network_security_config(name: str, root) -> NetworkSecurityConfig:
    config = NetworkSecurityConfig(path=name)

    def walk(node) -> None:
        tag = _local_name(node.tag)
        cleartext = _attr(node.attrib, "cleartextTrafficPermitted")
        if cleartext is not None:
            config.cleartext_traffic_permitted.append(
                {
                    "tag": tag,
                    "value": cleartext,
                }
            )
        src = _attr(node.attrib, "src")
        if tag == "certificates" and src:
            config.trust_anchors.append(src)
        for child in list(node):
            walk(child)

    walk(root)
    return config


def _scan_text_assets(profile: ApkProfile, archive: zipfile.ZipFile) -> None:
    for name in profile.asset_entries:
        suffix = Path(name).suffix.lower()
        if suffix not in TEXT_SCAN_EXTENSIONS:
            continue
        try:
            info = archive.getinfo(name)
        except KeyError:
            continue
        if info.file_size > 512 * 1024:
            continue
        try:
            text = archive.read(name).decode("utf-8", errors="ignore")
        except RuntimeError:
            continue
        for label, pattern in SECRET_PATTERNS.items():
            if pattern.search(text):
                profile.secret_indicators.append({"kind": label, "path": name})


def _attr(attrs: dict[str, str], name: str) -> str | None:
    return attrs.get(f"android:{name}") or attrs.get(name)


def _local_name(name: str) -> str:
    if "}" in name:
        return name.rsplit("}", 1)[1]
    return name

