from __future__ import annotations

import math
import re
from dataclasses import dataclass


@dataclass(frozen=True)
class SecretPattern:
    """A single detectable secret/credential shape shared by the static rule
    engine (apk.py/rules.py) and the deep indicator scanner (indicators.py)."""

    key: str
    label: str
    category: str
    severity: str
    confidence: str
    pattern: re.Pattern[str]
    description: str
    recommendation: str
    redact: bool = True


SECRET_PATTERNS: list[SecretPattern] = [
    SecretPattern(
        key="google_api_key",
        label="Google API key",
        category="secret",
        severity="high",
        confidence="high",
        pattern=re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
        description="Google API key-like value packaged in the APK.",
        recommendation="Restrict the key by package name and signing certificate, rotate if exposed, and move privileged operations server-side.",
    ),
    SecretPattern(
        key="aws_access_key",
        label="AWS access key ID",
        category="secret",
        severity="high",
        confidence="high",
        pattern=re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        description="AWS access key identifier packaged in the APK.",
        recommendation="Remove the key from client assets, rotate related credentials, and use short-lived server-issued tokens instead.",
    ),
    SecretPattern(
        key="private_key",
        label="Private key block",
        category="secret",
        severity="critical",
        confidence="high",
        pattern=re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
        description="Private key material marker found in packaged content.",
        recommendation="Remove private key material from the app package and rotate any certificate or credential pair that used it.",
    ),
    SecretPattern(
        key="slack_token",
        label="Slack token",
        category="secret",
        severity="high",
        confidence="high",
        pattern=re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"),
        description="Slack token-like value packaged in the APK.",
        recommendation="Revoke the token and move Slack/API automation behind a server-side integration.",
    ),
    SecretPattern(
        key="stripe_key",
        label="Stripe API key",
        category="secret",
        severity="critical",
        confidence="high",
        pattern=re.compile(r"\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{16,}\b"),
        description="Stripe secret/restricted API key packaged in the APK.",
        recommendation="Rotate the key immediately in the Stripe dashboard and move payment operations server-side only.",
    ),
    SecretPattern(
        key="twilio_key",
        label="Twilio API key",
        category="secret",
        severity="high",
        confidence="high",
        pattern=re.compile(r"\bSK[0-9a-fA-F]{32}\b"),
        description="Twilio API key SID packaged in the APK.",
        recommendation="Rotate the key in the Twilio console and proxy telephony/messaging operations through a backend service.",
    ),
    SecretPattern(
        key="sendgrid_key",
        label="SendGrid API key",
        category="secret",
        severity="high",
        confidence="high",
        pattern=re.compile(r"\bSG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43}\b"),
        description="SendGrid API key packaged in the APK.",
        recommendation="Revoke the key in SendGrid and send email only from a trusted backend service.",
    ),
    SecretPattern(
        key="jwt",
        label="JSON Web Token",
        category="secret",
        severity="medium",
        confidence="medium",
        pattern=re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}\b"),
        description="A JWT-shaped value packaged in the APK, which may be a long-lived test/service token.",
        recommendation="Confirm the token is not a long-lived credential, decode it to check for embedded secrets, and remove it if it grants standing access.",
    ),
    SecretPattern(
        key="basic_auth_url",
        label="Basic auth credential in URL",
        category="secret",
        severity="high",
        confidence="medium",
        pattern=re.compile(r"\bhttps?://[^\s\"'<>]{1,64}:[^\s\"'<>@]{1,64}@[A-Za-z0-9.-]+"),
        description="A URL containing an embedded username:password credential.",
        recommendation="Remove inline credentials from URLs, rotate the exposed credential, and use header-based or token-based authentication instead.",
    ),
    SecretPattern(
        key="generic_env_secret",
        label="Generic credential assignment",
        category="secret",
        severity="medium",
        confidence="low",
        pattern=re.compile(
            r"(?im)\b(?:api[_-]?key|secret|password|passwd|token|access[_-]?key)\s*[:=]\s*[\"']?[0-9A-Za-z_\-/+]{12,64}[\"']?"
        ),
        description="A key/value assignment shaped like a hardcoded credential (.env style).",
        recommendation="Confirm whether the value is a live credential; remove hardcoded secrets from client packages and load them from a secure backend at runtime.",
    ),
    SecretPattern(
        key="firebase_database_url",
        label="Firebase database URL",
        category="cloud",
        severity="medium",
        confidence="high",
        pattern=re.compile(r"https?://[A-Za-z0-9.-]+\.firebaseio\.com(?:/[^\s\"'<>]*)?"),
        description="Firebase Realtime Database endpoint found in packaged content.",
        recommendation="Review Firebase rules, require authentication for sensitive paths, and avoid trusting client-only authorization.",
        redact=False,
    ),
    SecretPattern(
        key="http_url",
        label="HTTP URL",
        category="network",
        severity="medium",
        confidence="medium",
        pattern=re.compile(r"\bhttp://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+"),
        description="Plain HTTP endpoint found in packaged content.",
        recommendation="Verify whether this endpoint is reachable in production and migrate sensitive traffic to HTTPS.",
        redact=False,
    ),
    SecretPattern(
        key="https_url",
        label="HTTPS URL",
        category="network",
        severity="info",
        confidence="medium",
        pattern=re.compile(r"\bhttps://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+"),
        description="HTTPS endpoint found in packaged content.",
        recommendation="Use this as an endpoint inventory seed for proxy testing and backend review.",
        redact=False,
    ),
    SecretPattern(
        key="ipv4_address",
        label="IPv4 address",
        category="network",
        severity="low",
        confidence="medium",
        pattern=re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"),
        description="IPv4 address found in packaged content.",
        recommendation="Confirm whether hardcoded IPs are production dependencies and whether TLS hostname validation still applies.",
        redact=False,
    ),
]

SECRET_ONLY_PATTERNS: list[SecretPattern] = [item for item in SECRET_PATTERNS if item.category in {"secret", "cloud"}]

IGNORED_URL_HOSTS = {
    "schemas.android.com",
    "www.w3.org",
}


def url_host(value: str) -> str:
    without_scheme = value.split("://", 1)[-1]
    return without_scheme.split("/", 1)[0].lower()


def mask(value: str) -> str:
    compact = value.replace("\n", "\\n")
    if len(compact) <= 10:
        return compact[:2] + "..." + compact[-2:]
    return compact[:6] + "..." + compact[-4:]


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())
