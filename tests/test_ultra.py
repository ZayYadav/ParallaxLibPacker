import importlib.util
import os
from pathlib import Path
import struct
import tempfile
import unittest

spec = importlib.util.spec_from_file_location(
    "parallax_ultra",
    Path(__file__).resolve().parents[1] / "scripts" / "parallax_ultra.py",
)
ultra = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ultra)


def make_arm64_so(path: Path, *, rwx=False, exec_stack=False):
    ident = bytearray(16)
    ident[:4] = b"\x7fELF"
    ident[4] = 2
    ident[5] = 1
    ident[6] = 1
    ehdr = bytes(ident) + struct.pack(
        "<HHIQQQIHHHHHH",
        ultra.ET_DYN,
        ultra.EM_AARCH64,
        1,
        0,
        64,
        0,
        0,
        64,
        56,
        2,
        0,
        0,
        0,
    )
    load_flags = 7 if rwx else 5
    load = struct.pack(
        "<IIQQQQQQ",
        ultra.PT_LOAD,
        load_flags,
        176,
        0x1000,
        0x1000,
        32,
        32,
        4096,
    )
    stack_flags = 7 if exec_stack else 6
    stack = struct.pack(
        "<IIQQQQQQ",
        ultra.PT_GNU_STACK,
        stack_flags,
        0,
        0,
        0,
        0,
        0,
        16,
    )
    path.write_bytes(ehdr + load + stack + os.urandom(32))


class UltraTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def test_accepts_hardened_arm64_shared_object(self):
        so = self.root / "lib.so"
        make_arm64_so(so)
        info = ultra.inspect_arm64_shared_elf(so)
        self.assertEqual(info["machine"], "AArch64")
        self.assertFalse(info["rwx_load"])

    def test_rejects_rwx_load(self):
        so = self.root / "rwx.so"
        make_arm64_so(so, rwx=True)
        with self.assertRaises(ultra.UltraError):
            ultra.inspect_arm64_shared_elf(so)

    def test_rejects_executable_stack(self):
        so = self.root / "stack.so"
        make_arm64_so(so, exec_stack=True)
        with self.assertRaises(ultra.UltraError):
            ultra.inspect_arm64_shared_elf(so)

    def test_manifest_signature_round_trip(self):
        keys = self.root / "keys"
        ultra.keygen(keys)
        message = b'{"schema":"test"}\n'
        sig = ultra.sign_manifest(message, keys / "signing.key")
        self.assertEqual(len(sig), 64)
        ultra.verify_manifest_signature(message, sig, keys / "verify.pub")
        with self.assertRaises(ultra.UltraError):
            ultra.verify_manifest_signature(message + b"x", sig, keys / "verify.pub")

    def test_exact_size_padding(self):
        p = self.root / "blob"
        p.write_bytes(b"abc")
        ultra.pad_to_size(p, 8192)
        self.assertEqual(p.stat().st_size, 8192)
        with self.assertRaises(ultra.UltraError):
            ultra.pad_to_size(p, 10)


if __name__ == "__main__":
    unittest.main()
