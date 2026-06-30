from __future__ import annotations

import json
import struct
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from apk_sentinel.core import scan_apk
from apk_sentinel.report import render_html, render_json


MANIFEST = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.insecure"
    android:versionCode="7"
    android:versionName="1.2.3">
    <uses-sdk android:minSdkVersion="21" android:targetSdkVersion="30" />
    <uses-permission android:name="android.permission.READ_SMS" />
    <application
        android:allowBackup="true"
        android:debuggable="true"
        android:usesCleartextTraffic="true"
        android:networkSecurityConfig="@xml/network_security_config">
        <activity android:name=".MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
            </intent-filter>
        </activity>
    </application>
</manifest>
"""

NETWORK_CONFIG = """<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="true">
        <trust-anchors>
            <certificates src="user" />
        </trust-anchors>
    </base-config>
</network-security-config>
"""


class ScanTests(unittest.TestCase):
    def test_scans_plaintext_manifest_apk(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            apk_path = Path(temp_dir) / "sample.apk"
            with zipfile.ZipFile(apk_path, "w") as archive:
                archive.writestr("AndroidManifest.xml", MANIFEST)
                archive.writestr("classes.dex", b"dex\n035\0")
                archive.writestr("lib/arm64-v8a/libdemo.so", b"\x7fELF")
                archive.writestr(
                    "META-INF/maven/com.squareup.okhttp3/okhttp/pom.properties",
                    "groupId=com.squareup.okhttp3\nartifactId=okhttp\nversion=4.9.0\n",
                )
                archive.writestr("res/xml/network_security_config.xml", NETWORK_CONFIG)
                archive.writestr("assets/config.txt", "aws_key=AKIAABCDEFGHIJKLMNOP")

            result = scan_apk(apk_path)
            rule_ids = {finding.rule_id for finding in result.findings}

            self.assertEqual(result.profile.package_name, "com.example.insecure")
            self.assertEqual(result.profile.target_sdk, 30)
            self.assertIn("android.permission.READ_SMS", result.profile.permissions)
            self.assertTrue(any(item["name"] == "com.squareup.okhttp3:okhttp" for item in result.profile.dependencies))
            self.assertTrue(any(item["name"] == "libdemo.so" for item in result.profile.dependencies))
            self.assertIn("manifest.debuggable", rule_ids)
            self.assertIn("manifest.exported_component", rule_ids)
            self.assertIn("network.cleartext_config", rule_ids)
            self.assertIn("assets.secret_indicator", rule_ids)

            report = json.loads(render_json(result))
            self.assertEqual(report["profile"]["file_name"], "sample.apk")
            self.assertGreaterEqual(len(report["findings"]), 6)
            self.assertIn("exploitability", report["findings"][0])
            self.assertIn("attack_path", report["findings"][0])
            self.assertIn("exploitation_chain", report["findings"][0])
            self.assertIn("evidence_quality", report["findings"][0])
            self.assertIn("references", report["findings"][0])
            self.assertTrue(any(item["purl"].startswith("pkg:maven/com/squareup/okhttp3/okhttp") for item in report["profile"]["dependencies"]))

            html_report = render_html(result)
            self.assertIn("Finding Triage", html_report)
            self.assertIn("Step-by-step Validation Chain", html_report)
            self.assertIn("Exploitability:", html_report)
            self.assertIn("PoC / References", html_report)

    def test_scans_binary_manifest_apk(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            apk_path = Path(temp_dir) / "binary.apk"
            with zipfile.ZipFile(apk_path, "w") as archive:
                archive.writestr("AndroidManifest.xml", _binary_manifest())
                archive.writestr("classes.dex", b"dex\n035\0")

            result = scan_apk(apk_path)
            rule_ids = {finding.rule_id for finding in result.findings}

            self.assertEqual(result.profile.package_name, "com.example.binary")
            self.assertEqual(result.profile.target_sdk, 34)
            self.assertEqual(len(result.profile.components), 1)
            self.assertEqual(result.profile.components[0].name, ".MainActivity")
            self.assertNotIn("parse.warning", rule_ids)
            self.assertIn("manifest.debuggable", rule_ids)
            self.assertIn("manifest.exported_component", rule_ids)

def _binary_manifest() -> bytes:
    strings = [
        "android",
        "http://schemas.android.com/apk/res/android",
        "manifest",
        "package",
        "com.example.binary",
        "uses-sdk",
        "minSdkVersion",
        "21",
        "targetSdkVersion",
        "34",
        "application",
        "debuggable",
        "true",
        "activity",
        "name",
        ".MainActivity",
        "exported",
    ]
    index = {value: position for position, value in enumerate(strings)}
    no_index = 0xFFFFFFFF
    android_uri = index["http://schemas.android.com/apk/res/android"]

    chunks = [
        _string_pool(strings),
        _namespace_chunk(0x0100, index["android"], android_uri),
        _start_element(
            index["manifest"],
            [
                (no_index, index["package"], index["com.example.binary"]),
            ],
        ),
        _start_element(
            index["uses-sdk"],
            [
                (android_uri, index["minSdkVersion"], index["21"]),
                (android_uri, index["targetSdkVersion"], index["34"]),
            ],
        ),
        _end_element(index["uses-sdk"]),
        _start_element(
            index["application"],
            [
                (android_uri, index["debuggable"], index["true"]),
            ],
        ),
        _start_element(
            index["activity"],
            [
                (android_uri, index["name"], index[".MainActivity"]),
                (android_uri, index["exported"], index["true"]),
            ],
        ),
        _end_element(index["activity"]),
        _end_element(index["application"]),
        _end_element(index["manifest"]),
        _namespace_chunk(0x0101, index["android"], android_uri),
    ]
    payload = b"".join(chunks)
    return struct.pack("<HHI", 0x0003, 8, 8 + len(payload)) + payload


def _string_pool(strings: list[str]) -> bytes:
    offsets: list[int] = []
    data = b""
    for value in strings:
        offsets.append(len(data))
        encoded = value.encode("utf-8")
        data += _len8(len(value)) + _len8(len(encoded)) + encoded + b"\0"
    data += b"\0" * ((4 - len(data) % 4) % 4)

    strings_start = 28 + len(strings) * 4
    body = (
        struct.pack("<IIIII", len(strings), 0, 0x00000100, strings_start, 0)
        + b"".join(struct.pack("<I", offset) for offset in offsets)
        + data
    )
    return struct.pack("<HHI", 0x0001, 28, 8 + len(body)) + body


def _len8(value: int) -> bytes:
    if value < 0x80:
        return bytes([value])
    return bytes([(value >> 8) | 0x80, value & 0xFF])


def _namespace_chunk(kind: int, prefix_idx: int, uri_idx: int) -> bytes:
    extension = struct.pack("<II", prefix_idx, uri_idx)
    return _node_chunk(kind, extension)


def _start_element(name_idx: int, attrs: list[tuple[int, int, int]]) -> bytes:
    no_index = 0xFFFFFFFF
    attr_items = b"".join(
        struct.pack("<IIIHBBI", ns_idx, attr_name_idx, raw_value_idx, 8, 0, 0x03, raw_value_idx)
        for ns_idx, attr_name_idx, raw_value_idx in attrs
    )
    extension = struct.pack("<IIHHHHHH", no_index, name_idx, 20, 20, len(attrs), 0, 0, 0) + attr_items
    return _node_chunk(0x0102, extension)


def _end_element(name_idx: int) -> bytes:
    return _node_chunk(0x0103, struct.pack("<II", 0xFFFFFFFF, name_idx))


def _node_chunk(kind: int, extension: bytes) -> bytes:
    line_number = 1
    comment = 0xFFFFFFFF
    return struct.pack("<HHIII", kind, 16, 16 + len(extension), line_number, comment) + extension


if __name__ == "__main__":
    unittest.main()
