"""TLS trust for Apple endpoints.

Apple's GrandSlam endpoint (gsa.apple.com) presents a certificate chain that
terminates at Apple's own self-signed root ("Apple Root CA"), which is NOT
part of the WebPKI trust stores `requests` uses by default on Linux - certifi
(Mozilla's store) carries no Apple roots at all. Verifying that endpoint with
the default store fails with "self-signed certificate in certificate chain" -
the reason the original code disabled certificate verification entirely.

Disabling verification is the wrong fix: it exposes the password-equivalent
tokens in the auth headers to any network-level man-in-the-middle. The right
fix is to trust Apple's actual roots: this module ships Apple's official root
certificates (downloaded from https://www.apple.com/certificateauthority/)
and builds a CA bundle of WebPKI (certifi) + the pinned Apple roots.

The bundled certificate files are pinned by SHA-256 fingerprint (the values
published in Apple's trusted-root lists and in Apple's open-source
SecAppleAnchor.c) and checked on every use, so the files cannot be silently
swapped for an attacker's root. A MITM presenting any other certificate - a
corporate proxy root, a rogue Wi-Fi box - still fails verification, loudly.
"""

from __future__ import annotations

import os

import certifi
from cryptography import x509
from cryptography.hazmat.primitives import hashes

from . import paths

# SHA-256 fingerprints of the DER-encoded certificates, pinned to Apple's
# published values (https://support.apple.com/en-us/103272 and kin,
# opensource.apple.com SecAppleAnchor.c).
_PINNED_SHA256 = {
    "apple_root_ca_g1.crt":
        "B0:B1:73:0E:CB:C7:FF:45:05:14:2C:49:F1:29:5E:6E:DA:6B:CA:ED:7E:2C:68:C5:BE:91:B5:A1:10:01:F0:24",
    "apple_root_ca_g3.crt":
        "63:34:3A:BF:B8:9A:6A:03:EB:B5:7E:9B:3F:5F:A7:BE:7C:4F:5C:75:6F:30:17:B3:A8:C4:88:C3:65:3E:91:79",
}

_BUNDLE: str | None = None


def _cert_dir() -> str:
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "certs")


def check_pinned(name: str, data: bytes) -> None:
    """Assert that a bundled certificate matches its pinned fingerprint."""
    expected = _PINNED_SHA256[name]
    fingerprint = x509.load_pem_x509_certificate(data).fingerprint(hashes.SHA256())
    actual = fingerprint.hex(":").upper()
    if actual != expected:
        raise RuntimeError(
            f"{name} fingerprint mismatch: bundled {actual} != pinned {expected} - "
            "refusing to trust it (the file may have been tampered with)")


def apple_roots() -> bytes:
    """The concatenated, fingerprint-checked Apple root certificates."""
    parts = []
    for name in _PINNED_SHA256:
        with open(os.path.join(_cert_dir(), name), "rb") as f:
            data = f.read()
        check_pinned(name, data)
        parts.append(data if data.endswith(b"\n") else data + b"\n")
    return b"".join(parts)


def ca_bundle() -> str:
    """Path to a CA bundle covering every endpoint icp talks to: certifi's
    WebPKI roots plus Apple's own pinned roots. Built once per process and
    cached in the (0700) config dir."""
    global _BUNDLE
    if _BUNDLE is not None:
        return _BUNDLE
    with open(certifi.where(), "rb") as f:
        webpki = f.read()
    content = webpki if webpki.endswith(b"\n") else webpki + b"\n"
    content += apple_roots()
    bundle = paths.config_dir() / "ca-bundle.crt"
    if not bundle.exists() or bundle.read_bytes() != content:
        fd = os.open(bundle, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(content)
        os.chmod(bundle, 0o600)
    _BUNDLE = str(bundle)
    return _BUNDLE
