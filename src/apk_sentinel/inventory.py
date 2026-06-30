from __future__ import annotations

import configparser
import re
import zipfile
from pathlib import Path


def extract_dependency_inventory(archive_or_path: zipfile.ZipFile | str | Path) -> list[dict[str, str]]:
    if isinstance(archive_or_path, zipfile.ZipFile):
        return _extract_from_archive(archive_or_path)
    with zipfile.ZipFile(archive_or_path) as archive:
        return _extract_from_archive(archive)


def _extract_from_archive(archive: zipfile.ZipFile) -> list[dict[str, str]]:
    dependencies: dict[str, dict[str, str]] = {}
    names = archive.namelist()

    for name in names:
        normalized = name.replace("\\", "/")
        lower = normalized.lower()
        if lower.endswith("pom.properties") and "/meta-inf/maven/" in f"/{lower}":
            component = _component_from_pom_properties(archive, normalized)
            if component:
                dependencies[_component_key(component)] = component
        elif lower.endswith(".properties"):
            component = _component_from_android_properties(archive, normalized)
            if component:
                dependencies[_component_key(component)] = component

    for name in names:
        normalized = name.replace("\\", "/")
        if normalized.startswith("lib/") and normalized.endswith(".so"):
            component = _native_component(normalized)
            dependencies.setdefault(_component_key(component), component)

    for component in _framework_signals(names):
        dependencies.setdefault(_component_key(component), component)

    return sorted(
        dependencies.values(),
        key=lambda item: (
            item.get("ecosystem", ""),
            item.get("name", ""),
            item.get("version", ""),
            item.get("evidence", ""),
        ),
    )


def _component_from_pom_properties(archive: zipfile.ZipFile, name: str) -> dict[str, str] | None:
    try:
        data = archive.read(name).decode("utf-8", errors="replace")
    except (KeyError, RuntimeError):
        return None
    props = _parse_properties(data)
    group_id = props.get("groupId") or _maven_path_part(name, -3)
    artifact_id = props.get("artifactId") or _maven_path_part(name, -2)
    version = props.get("version", "")
    if not group_id or not artifact_id:
        return None
    package_name = f"{group_id}:{artifact_id}"
    return {
        "type": "maven-package",
        "ecosystem": "Maven",
        "name": package_name,
        "version": version,
        "purl": _purl("maven", group_id, artifact_id, version),
        "evidence": name,
        "confidence": "high",
        "source": "META-INF/maven pom.properties",
    }


def _component_from_android_properties(archive: zipfile.ZipFile, name: str) -> dict[str, str] | None:
    filename = Path(name).name
    if not filename.endswith(".properties"):
        return None
    stem = filename.removesuffix(".properties")
    known_prefixes = ("play-services-", "firebase-", "google-", "androidx.")
    if not stem.startswith(known_prefixes):
        return None
    try:
        data = archive.read(name).decode("utf-8", errors="replace")
    except (KeyError, RuntimeError):
        return None
    props = _parse_properties(data)
    version = props.get("version") or props.get("VERSION_NAME") or props.get("project.version") or ""
    if stem.startswith("play-services-"):
        group_id = "com.google.android.gms"
        artifact_id = stem
    elif stem.startswith("firebase-"):
        group_id = "com.google.firebase"
        artifact_id = stem
    elif stem.startswith("androidx."):
        parts = stem.split(".")
        group_id = ".".join(parts[:2]) if len(parts) >= 2 else "androidx"
        artifact_id = stem
    else:
        group_id = "com.google.android"
        artifact_id = stem
    package_name = f"{group_id}:{artifact_id}"
    return {
        "type": "android-sdk-package",
        "ecosystem": "Maven",
        "name": package_name,
        "version": version,
        "purl": _purl("maven", group_id, artifact_id, version),
        "evidence": name,
        "confidence": "medium" if version else "low",
        "source": "Android SDK properties",
    }


def _native_component(name: str) -> dict[str, str]:
    parts = name.split("/")
    abi = parts[1] if len(parts) > 2 else "unknown"
    library = parts[-1]
    return {
        "type": "native-library",
        "ecosystem": "Native",
        "name": library,
        "version": "",
        "purl": "",
        "evidence": name,
        "confidence": "medium",
        "source": f"APK native library ({abi})",
    }


def _framework_signals(names: list[str]) -> list[dict[str, str]]:
    lower_names = {name.lower().replace("\\", "/") for name in names}
    signals: list[dict[str, str]] = []
    checks = [
        ("Flutter", "flutter", ["lib/arm64-v8a/libflutter.so", "assets/flutter_assets/isolate_snapshot_data"]),
        ("Unity", "unity", ["lib/arm64-v8a/libunity.so", "assets/bin/data/globalgamemanagers"]),
        ("React Native", "react-native", ["assets/index.android.bundle", "lib/arm64-v8a/libreactnativejni.so"]),
        ("Cordova", "cordova", ["assets/www/cordova.js"]),
    ]
    for label, name, needles in checks:
        evidence = next((needle for needle in needles if needle in lower_names), "")
        if not evidence:
            continue
        signals.append(
            {
                "type": "framework",
                "ecosystem": "Framework",
                "name": label,
                "version": "",
                "purl": "",
                "evidence": evidence,
                "confidence": "medium",
                "source": "Framework fingerprint",
            }
        )
    return signals


def _parse_properties(data: str) -> dict[str, str]:
    parser = configparser.ConfigParser()
    parser.optionxform = str
    try:
        parser.read_string("[props]\n" + data)
    except configparser.Error:
        props: dict[str, str] = {}
        for line in data.splitlines():
            if "=" not in line or line.strip().startswith("#"):
                continue
            key, value = line.split("=", 1)
            props[key.strip()] = value.strip()
        return props
    return {key: value.strip() for key, value in parser.items("props")}


def _maven_path_part(name: str, index: int) -> str:
    parts = name.replace("\\", "/").split("/")
    try:
        return parts[index]
    except IndexError:
        return ""


def _purl(kind: str, group_id: str, artifact_id: str, version: str) -> str:
    namespace = group_id.replace(".", "/")
    base = f"pkg:{kind}/{namespace}/{artifact_id}"
    if version:
        return f"{base}@{version}"
    return base


def _component_key(component: dict[str, str]) -> str:
    identity = "|".join(
        [
            component.get("ecosystem", ""),
            component.get("name", ""),
            component.get("version", ""),
            component.get("evidence", ""),
        ]
    )
    return re.sub(r"\s+", " ", identity)
