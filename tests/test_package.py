import importlib.util
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

    def test_tampering_rejected_before_decrypt(self):
        original = self.sealed.read_bytes()
        for offset in (0, 8, 16, package.HEADER.size, len(original) - 65, len(original) - 1):
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
