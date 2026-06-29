from __future__ import annotations

import hashlib
import ipaddress
from datetime import datetime, timedelta, timezone
from pathlib import Path

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
except Exception:  # pragma: no cover - exercised only when optional dependency is absent.
    x509 = None
    hashes = None
    serialization = None
    rsa = None
    ExtendedKeyUsageOID = None
    NameOID = None


CA_DIR_NAME = "ca"
CA_KEY_NAME = "apk-sentinel-ca.key"
CA_CERT_NAME = "apk-sentinel-ca.pem"

CA_EXPORT_PROFILES = [
    {
        "id": "browser-cer",
        "label": "Browser / Brave",
        "description": "DER .cer for Windows or Chromium certificate import.",
        "download_name": "apk-sentinel-browser-ca.cer",
        "extension": ".cer",
    },
    {
        "id": "pem",
        "label": "PEM / Tools",
        "description": "PEM certificate for tools and manual trust stores.",
        "download_name": "apk-sentinel-ca.pem",
        "extension": ".pem",
    },
    {
        "id": "android-user",
        "label": "Android User CA",
        "description": "DER .crt for Android credential installation.",
        "download_name": "apk-sentinel-android-user-ca.crt",
        "extension": ".crt",
    },
    {
        "id": "android-system",
        "label": "Android System CA",
        "description": "PEM certificate named for Android system CA stores.",
        "download_name": "android-system-ca.0",
        "extension": ".0",
    },
]


def cryptography_available() -> bool:
    return all(item is not None for item in (x509, hashes, serialization, rsa, ExtendedKeyUsageOID, NameOID))


def ensure_ca(storage_dir: Path) -> dict:
    if not cryptography_available():
        raise RuntimeError("Install the cryptography package to generate a local CA certificate.")

    paths = ca_paths(storage_dir)
    paths["dir"].mkdir(parents=True, exist_ok=True)
    if paths["cert"].exists() and paths["key"].exists():
        return ca_status(storage_dir)

    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "APK Sentinel"),
            x509.NameAttribute(NameOID.COMMON_NAME, "APK Sentinel Local Testing CA"),
        ]
    )
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1825))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=False,
                key_cert_sign=True,
                key_agreement=False,
                content_commitment=False,
                data_encipherment=False,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )

    paths["key"].write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    paths["cert"].write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return ca_status(storage_dir)


def ca_status(storage_dir: Path) -> dict:
    paths = ca_paths(storage_dir)
    status = {
        "available": cryptography_available(),
        "exists": paths["cert"].exists() and paths["key"].exists(),
        "cert_path": str(paths["cert"]),
        "key_path": str(paths["key"]),
        "fingerprint": "",
        "subject": "",
        "not_valid_after": "",
        "android_subject_hash": "",
        "android_system_name": "",
        "profiles": [dict(profile) for profile in CA_EXPORT_PROFILES],
        "error": None,
    }

    if not status["available"]:
        status["error"] = "cryptography package is not installed"
        return status
    if not status["exists"]:
        return status

    try:
        cert = x509.load_pem_x509_certificate(paths["cert"].read_bytes())
        fingerprint = cert.fingerprint(hashes.SHA256()).hex().upper()
        subject_hash = android_subject_hash(cert)
        status["fingerprint"] = ":".join(fingerprint[index : index + 2] for index in range(0, len(fingerprint), 2))
        status["subject"] = cert.subject.rfc4514_string()
        status["not_valid_after"] = cert.not_valid_after_utc.isoformat()
        status["android_subject_hash"] = subject_hash
        status["android_system_name"] = f"{subject_hash}.0"
        for profile in status["profiles"]:
            if profile["id"] == "android-system":
                profile["download_name"] = status["android_system_name"]
    except Exception as exc:
        status["exists"] = False
        status["error"] = str(exc)
    return status


def export_ca(storage_dir: Path, profile_id: str) -> dict:
    if not cryptography_available():
        raise RuntimeError("Install the cryptography package to export a local CA certificate.")

    profile = _profile(profile_id)
    cert = _load_cert(storage_dir)
    if profile["id"] in {"browser-cer", "android-user"}:
        data = cert.public_bytes(serialization.Encoding.DER)
        mimetype = "application/x-x509-ca-cert"
    else:
        data = cert.public_bytes(serialization.Encoding.PEM)
        mimetype = "application/x-pem-file"

    download_name = profile["download_name"]
    if profile["id"] == "android-system":
        download_name = f"{android_subject_hash(cert)}.0"

    return {
        "data": data,
        "download_name": download_name,
        "mimetype": mimetype,
        "profile": profile,
    }


def ensure_host_certificate(storage_dir: Path, cache_dir: Path, hostname: str) -> dict[str, Path]:
    if not cryptography_available():
        raise RuntimeError("Install the cryptography package to generate HTTPS interception certificates.")

    paths = ca_paths(storage_dir)
    if not paths["cert"].exists() or not paths["key"].exists():
        raise FileNotFoundError("Generate and install the local CA before HTTPS interception.")

    cache_dir.mkdir(parents=True, exist_ok=True)
    safe_name = hashlib.sha256(hostname.encode("utf-8")).hexdigest()[:24]
    cert_path = cache_dir / f"{safe_name}.pem"
    key_path = cache_dir / f"{safe_name}.key"
    if cert_path.exists() and key_path.exists():
        return {"cert": cert_path, "key": key_path}

    ca_cert = x509.load_pem_x509_certificate(paths["cert"].read_bytes())
    ca_key = serialization.load_pem_private_key(paths["key"].read_bytes(), password=None)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(timezone.utc)
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "APK Sentinel MITM"),
            x509.NameAttribute(NameOID.COMMON_NAME, hostname),
        ]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=825))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                key_cert_sign=False,
                key_agreement=False,
                content_commitment=False,
                data_encipherment=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.SubjectAlternativeName([_san_name(hostname)]), critical=False)
        .sign(ca_key, hashes.SHA256())
    )

    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return {"cert": cert_path, "key": key_path}


def android_subject_hash(cert) -> str:
    digest = hashlib.md5(cert.subject.public_bytes()).digest()
    return f"{int.from_bytes(digest[:4], 'little'):08x}"


def ca_paths(storage_dir: Path) -> dict[str, Path]:
    ca_dir = storage_dir / "proxy_lab" / CA_DIR_NAME
    return {
        "dir": ca_dir,
        "key": ca_dir / CA_KEY_NAME,
        "cert": ca_dir / CA_CERT_NAME,
    }


def _load_cert(storage_dir: Path):
    paths = ca_paths(storage_dir)
    if not paths["cert"].exists():
        raise FileNotFoundError("Generate the local CA first.")
    return x509.load_pem_x509_certificate(paths["cert"].read_bytes())


def _profile(profile_id: str) -> dict:
    for profile in CA_EXPORT_PROFILES:
        if profile["id"] == profile_id:
            return dict(profile)
    valid = ", ".join(profile["id"] for profile in CA_EXPORT_PROFILES)
    raise ValueError(f"Unknown CA export profile '{profile_id}'. Choose one of: {valid}.")


def _san_name(hostname: str):
    try:
        return x509.IPAddress(ipaddress.ip_address(hostname))
    except ValueError:
        return x509.DNSName(hostname)
