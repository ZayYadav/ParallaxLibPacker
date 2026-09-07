import importlib.util
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from cryptography.exceptions import InvalidSignature, InvalidTag

spec = importlib.util.spec_from_file_location(
    "package", Path(__file__).resolve().parents[1] / "scripts/parallax_package.py"
)
package = importlib.util.module_from_spec(spec)
spec.loader.exec_module(package)


class PackageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.keys = self.root / "keys"
        package.generate_keys(self.keys)
        self.enc = self.keys / "encryption.key"
        self.sign = self.keys / "signing.key"
        self.pub = self.keys / "verify.pub"
        self.source = self.root / "input.so"
        self.original = b"\x7fELF" + os.urandom(4096)
        self.source.write_bytes(self.original)
        self.sealed = self.root / "input.plpkg"
        self.output = self.root / "restored.so"
        package.seal(self.source, self.sealed, self.enc, self.sign)

    def test_round_trip(self):
        package.restore(self.sealed, self.output, self.enc, self.pub)
        self.assertEqual(self.original, self.output.read_bytes())
        if os.name == "posix":
            self.assertEqual(self.output.stat().st_mode & 0o777, 0o600)

    def test_fresh_encryption(self):
        other = self.root / "other.plpkg"
        package.seal(self.source, other, self.enc, self.sign)
        self.assertNotEqual(self.sealed.read_bytes(), other.read_bytes())

    def test_arbitrary_library_names_and_contents(self):
        for index, name in enumerate(("libaudio.so", "libpayment.so", "custom module.so", "native.dll")):
            with self.subTest(name=name):
                source = self.root / name
                payload = os.urandom(31 + index * 777)
                source.write_bytes(payload)
                sealed = self.root / f"{index}.plpkg"
                restored = self.root / f"{index}.restored"
                package.seal(source, sealed, self.enc, self.sign)
                verified = package.verified_package(sealed, self.pub)
                self.assertEqual(verified[3], {"name": name, "size": len(payload),
                                               "sha256": hashlib.sha256(payload).hexdigest()})
                self.assertEqual(package.decrypt_verified(verified, self.enc), payload)
                package.restore(sealed, restored, self.enc, self.pub)
                self.assertEqual(restored.read_bytes(), payload)

    def rewrite_signed_metadata(self, metadata):
        # Produce an authenticated but internally inconsistent package, as a faulty
        # publisher might, so these tests exercise checks beyond signature validity.
        nonce = os.urandom(12)
        header = package.HEADER.pack(package.MAGIC, len(self.original), len(metadata), nonce)
        aad = header + metadata
        body = aad + package.AESGCM(self.enc.read_bytes()).encrypt(nonce, self.original, aad)
        signer = package.Ed25519PrivateKey.from_private_bytes(self.sign.read_bytes())
        self.sealed.write_bytes(body + signer.sign(body))

    def test_signed_wrong_digest_rejected(self):
        metadata = {"name": "input.so", "size": len(self.original), "sha256": "0" * 64}
        self.rewrite_signed_metadata(json.dumps(metadata).encode("ascii"))
        with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
            package.restore(self.sealed, self.output, self.enc, self.pub)
        self.assertFalse(self.output.exists())

    def test_signed_malformed_metadata_rejected(self):
        valid = {"name": "input.so", "size": len(self.original),
                 "sha256": hashlib.sha256(self.original).hexdigest()}
        cases = [b"[]", b"{", b"\xff", b'{"name":"one","name":"two"}',
                 json.dumps({**valid, "size": True}).encode(),
                 json.dumps({**valid, "sha256": "x" * 64}).encode(),
                 json.dumps({**valid, "extra": 1}).encode()]
        for metadata in cases:
            with self.subTest(metadata=metadata):
                self.rewrite_signed_metadata(metadata)
                with self.assertRaises(ValueError):
                    package.restore(self.sealed, self.output, self.enc, self.pub)
                self.assertFalse(self.output.exists())

    def test_stored_filename_is_not_an_output_path(self):
        metadata = {"name": "../outside.so", "size": len(self.original),
                    "sha256": hashlib.sha256(self.original).hexdigest()}
        self.rewrite_signed_metadata(json.dumps(metadata).encode("ascii"))
        package.restore(self.sealed, self.output, self.enc, self.pub)
        self.assertEqual(self.output.read_bytes(), self.original)
        self.assertFalse((self.root / "outside.so").exists())

    def test_signature_does_not_replace_gcm_verification(self):
        body = bytearray(self.sealed.read_bytes()[:-64])
        body[-1] ^= 1
        signer = package.Ed25519PrivateKey.from_private_bytes(self.sign.read_bytes())
        self.sealed.write_bytes(bytes(body) + signer.sign(bytes(body)))
        with self.assertRaises(InvalidTag):
            package.restore(self.sealed, self.output, self.enc, self.pub)
        self.assertFalse(self.output.exists())

    def test_tampering_rejected_before_decrypt(self):
        original = self.sealed.read_bytes()
        for offset in (0, 8, 16, 20, package.HEADER.size, len(original) - 65, len(original) - 1):
            with self.subTest(offset=offset):
                altered = bytearray(original)
                altered[offset] ^= 1
                self.sealed.write_bytes(altered)
                with patch.object(package.AESGCM, "decrypt") as decrypt:
                    with self.assertRaises((ValueError, InvalidSignature)):
                        package.restore(self.sealed, self.output, self.enc, self.pub)
                    decrypt.assert_not_called()
                self.assertFalse(self.output.exists())

    def test_truncation_and_trailing_data(self):
        original = self.sealed.read_bytes()
        for data in (b"", original[:20], original[:-1], original + b"x"):
            self.sealed.write_bytes(data)
            with self.assertRaises(ValueError):
                package.restore(self.sealed, self.output, self.enc, self.pub)
            self.assertFalse(self.output.exists())

    def test_wrong_keys(self):
        other = self.root / "other-keys"
        package.generate_keys(other)
        with self.assertRaises(InvalidSignature):
            package.restore(self.sealed, self.output, self.enc, other / "verify.pub")
        with self.assertRaises(InvalidTag):
            package.restore(self.sealed, self.output, other / "encryption.key", self.pub)
        self.assertFalse(self.output.exists())

    def test_existing_output_preserved(self):
        self.output.write_bytes(b"keep")
        with self.assertRaises(FileExistsError):
            package.restore(self.sealed, self.output, self.enc, self.pub)
        self.assertEqual(self.output.read_bytes(), b"keep")
        with self.assertRaises(FileExistsError):
            package.seal(self.source, self.source, self.enc, self.sign)
        self.assertEqual(self.source.read_bytes(), self.original)

    def test_keygen_refuses_existing_directory(self):
        original = self.sign.read_bytes()
        with self.assertRaises(FileExistsError):
            package.generate_keys(self.keys)
        self.assertEqual(self.sign.read_bytes(), original)

    def test_invalid_key_and_size_limits(self):
        self.enc.write_bytes(b"short")
        with self.assertRaises(ValueError):
            package.restore(self.sealed, self.output, self.enc, self.pub)
        with self.assertRaises(ValueError):
            package.read_bounded(self.source, 10)
        self.source.write_bytes(b"")
        with self.assertRaises(ValueError):
            package.seal(self.source, self.output, self.enc, self.sign)
        self.assertFalse(self.output.exists())


if __name__ == "__main__":
    unittest.main()
