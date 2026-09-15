"""Tests for the pinned Apple root CA bundle (icp/tls.py). Offline."""

import os
import tempfile
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes

from icp import tls


class TestAppleRoots(unittest.TestCase):
    def setUp(self):
        self._old_xdg = os.environ.get("XDG_CONFIG_HOME")
        self._tmp = tempfile.TemporaryDirectory()
        os.environ["XDG_CONFIG_HOME"] = self._tmp.name
        tls._BUNDLE = None   # reset the per-process cache

    def tearDown(self):
        if self._old_xdg is None:
            os.environ.pop("XDG_CONFIG_HOME", None)
        else:
            os.environ["XDG_CONFIG_HOME"] = self._old_xdg
        tls._BUNDLE = None
        self._tmp.cleanup()

    def test_bundled_roots_match_pins(self):
        """The shipped certificates carry exactly the pinned fingerprints."""
        for name in tls._PINNED_SHA256:
            with open(os.path.join(tls._cert_dir(), name), "rb") as f:
                tls.check_pinned(name, f.read())   # must not raise

    def test_tampered_root_is_rejected(self):
        """A certificate whose fingerprint is not pinned must be refused."""
        # Sign a self-signed cert with cryptography and try to pin it as G1.
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography import x509 as x
        from datetime import datetime, timezone
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cert = (x.CertificateBuilder()
                .subject_name(x.Name([]))
                .issuer_name(x.Name([]))
                .public_key(key.public_key())
                .serial_number(1)
                .not_valid_before(datetime.now(timezone.utc))
                .not_valid_after(datetime.now(timezone.utc))
                .sign(key, hashes.SHA256()))
        with self.assertRaises(RuntimeError):
            tls.check_pinned("apple_root_ca_g1.crt", cert.public_bytes(
                __import__("cryptography.hazmat.primitives.serialization",
                           fromlist=["Encoding"]).Encoding.PEM))

    def test_ca_bundle_contains_webpki_and_apple(self):
        path = tls.ca_bundle()
        self.assertTrue(os.path.isfile(path))
        data = open(path, "rb").read()
        # both Apple roots present, as parseable certs with the pinned prints
        loaded = x509.load_pem_x509_certificates(data)
        subjects = {c.subject.rfc4514_string() for c in loaded}
        self.assertIn("CN=Apple Root CA,OU=Apple Certification Authority,O=Apple Inc.,C=US",
                      subjects)
        self.assertIn("C=US,O=Apple Inc.,OU=Apple Certification Authority,CN=Apple Root CA - G3",
                      subjects)
        # certifi's WebPKI roots are in there too (hundreds of CAs)
        self.assertGreater(len(loaded), 100)

    def test_bundle_cached_and_private(self):
        path = tls.ca_bundle()
        self.assertEqual(tls.ca_bundle(), path)          # cached: same path back
        self.assertEqual(os.stat(path).st_mode & 0o077, 0)  # not group/world accessible


if __name__ == "__main__":
    unittest.main()


class TestVerifyValues(unittest.TestCase):
    """verify= kwargs must be a bool or an existing CA-bundle path, never a function ref."""

    def test_cloudkit_verify_tls_is_a_path(self):
        from icp.transport import cloudkit
        v = cloudkit.VERIFY_TLS
        self.assertIsInstance(v, str, "VERIFY_TLS must be a path string (ca_bundle() call)")
        self.assertTrue(os.path.isabs(v) and os.path.isfile(v))
