from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass, field

from apk_sentinel.models import AppComponent

ANDROID_NS = "http://schemas.android.com/apk/res/android"


@dataclass
class ManifestData:
    package_name: str | None = None
    version_code: str | None = None
    version_name: str | None = None
    min_sdk: int | None = None
    target_sdk: int | None = None
    permissions: list[str] = field(default_factory=list)
    application_attrs: dict[str, str] = field(default_factory=dict)
    components: list[AppComponent] = field(default_factory=list)


def parse_manifest_tree(root: ET.Element) -> ManifestData:
    data = ManifestData(
        package_name=root.attrib.get("package"),
        version_code=_attr(root.attrib, "versionCode"),
        version_name=_attr(root.attrib, "versionName"),
    )

    for child in list(root):
        tag = _local_name(child.tag)
        if tag == "uses-sdk":
            data.min_sdk = _int_or_none(_attr(child.attrib, "minSdkVersion"))
            data.target_sdk = _int_or_none(_attr(child.attrib, "targetSdkVersion"))
        elif tag in {"uses-permission", "uses-permission-sdk-23"}:
            name = _attr(child.attrib, "name")
            if name and name not in data.permissions:
                data.permissions.append(name)
        elif tag == "application":
            data.application_attrs = _normalize_attrs(child.attrib)
            data.components.extend(_parse_components(child))

    data.permissions.sort()
    return data


def _parse_components(application: ET.Element) -> list[AppComponent]:
    components: list[AppComponent] = []
    for child in list(application):
        kind = _local_name(child.tag)
        if kind not in {"activity", "activity-alias", "service", "receiver", "provider"}:
            continue
        intent_filters = sum(1 for grandchild in list(child) if _local_name(grandchild.tag) == "intent-filter")
        components.append(
            AppComponent(
                kind=kind,
                name=_attr(child.attrib, "name"),
                exported=_bool_or_none(_attr(child.attrib, "exported")),
                permission=_attr(child.attrib, "permission"),
                intent_filters=intent_filters,
            )
        )
    return components


def _normalize_attrs(attrs: dict[str, str]) -> dict[str, str]:
    return {_normalize_attr_name(key): value for key, value in attrs.items()}


def _attr(attrs: dict[str, str], name: str) -> str | None:
    return attrs.get(f"android:{name}") or attrs.get(name) or attrs.get(f"{{{ANDROID_NS}}}{name}")


def _normalize_attr_name(name: str) -> str:
    prefix = f"{{{ANDROID_NS}}}"
    if name.startswith(prefix):
        return "android:" + name.removeprefix(prefix)
    return name


def _local_name(name: str) -> str:
    if "}" in name:
        return name.rsplit("}", 1)[1]
    return name


def _bool_or_none(value: str | None) -> bool | None:
    if value is None:
        return None
    if value.lower() == "true":
        return True
    if value.lower() == "false":
        return False
    return None


def _int_or_none(value: str | None) -> int | None:
    if value is None:
        return None
    try:
        return int(value, 0)
    except ValueError:
        return None

