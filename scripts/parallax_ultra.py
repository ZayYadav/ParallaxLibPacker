#!/usr/bin/env python3
"""Parallax Ultra client-side protection frontend.

This tool deliberately exposes no restore/unpack command. The native packer
performs PVM4 transport diversification; this frontend adds strict ELF policy,
atomic output, optional size equalization, and signed provenance.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import secrets
import struct
import subprocess
import sys
import tempfile
from datetime import datetime, timezone

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

# Keys, manifests and temporary protection products default to owner-only.
if os.name == "posix":
    os.umask(0o077)

SCHEMA = "parallax-ultra-manifest-v2"
PROFILE = "parallax-pvm4-arm64-v2"
MAX_LIB_SIZE = 1024 * 1024 * 1024
PT_LOAD = 1
PT_GNU_STACK = 0x6474E551
PF_X = 1
PF_W = 2
ET_DYN = 3
EM_AARCH64 = 183


class UltraError(RuntimeError):
    pass


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    total = 0
    with path.open("rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_LIB_SIZE:
                raise UltraError("file exceeds 1 GiB policy limit")
            h.update(chunk)
    return h.hexdigest()


def read_exact(path: Path, offset: int, size: int) -> bytes:
    if offset < 0 or size < 0:
        raise UltraError("invalid file range")
    with path.open("rb") as f:
        f.seek(offset)
        data = f.read(size)
    if len(data) != size:
        raise UltraError("truncated ELF")
    return data


def inspect_arm64_shared_elf(path: Path) -> dict:
    if path.is_symlink():
        raise UltraError("symlink inputs/outputs are not accepted")
    st = path.stat()
    if st.st_size <= 0 or st.st_size > MAX_LIB_SIZE:
        raise UltraError("ELF size outside policy")

    hdr = read_exact(path, 0, 64)
    if hdr[:4] != b"\x7fELF":
        raise UltraError("input is not ELF")
    if hdr[4] != 2 or hdr[5] != 1:
        raise UltraError("only little-endian ELF64 is supported")

    e_type, e_machine = struct.unpack_from("<HH", hdr, 16)
    if e_type != ET_DYN:
        raise UltraError("input must be ET_DYN shared object")
    if e_machine != EM_AARCH64:
        raise UltraError("ultra profile currently supports ARM64/AArch64 only")

    e_phoff = struct.unpack_from("<Q", hdr, 32)[0]
    e_phentsize = struct.unpack_from("<H", hdr, 54)[0]
    e_phnum = struct.unpack_from("<H", hdr, 56)[0]
    if e_phentsize != 56 or not (1 <= e_phnum <= 256):
        raise UltraError("invalid program-header table")
    table_size = e_phentsize * e_phnum
    if e_phoff > st.st_size or table_size > st.st_size - e_phoff:
        raise UltraError("program-header table outside file")

    phdrs = read_exact(path, e_phoff, table_size)
    load_count = 0
    stack_seen = False
    relro_safe = True
    for i in range(e_phnum):
        off = i * e_phentsize
        p_type, p_flags = struct.unpack_from("<II", phdrs, off)
        p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = struct.unpack_from(
            "<QQQQQQ", phdrs, off + 8
        )
        if p_filesz > 0 and (p_offset > st.st_size or p_filesz > st.st_size - p_offset):
            raise UltraError("PT segment outside file")
        if p_memsz < p_filesz:
            raise UltraError("PT segment memsz smaller than filesz")
        if p_type == PT_LOAD:
            load_count += 1
            if (p_flags & PF_W) and (p_flags & PF_X):
                relro_safe = False
                raise UltraError("RWX PT_LOAD rejected")
        elif p_type == PT_GNU_STACK:
            stack_seen = True
            if p_flags & PF_X:
                raise UltraError("executable GNU_STACK rejected")

    if load_count == 0:
        raise UltraError("ELF contains no PT_LOAD")
    return {
        "elf_class": 64,
        "machine": "AArch64",
        "type": "ET_DYN",
        "program_headers": e_phnum,
        "load_segments": load_count,
        "gnu_stack_present": stack_seen,
        "rwx_load": not relro_safe,
    }


def write_new(path: Path, data: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(path, flags, mode)
    try:
        with os.fdopen(fd, "wb") as out:
            out.write(data)
            out.flush()
            os.fsync(out.fileno())
    except BaseException:
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        raise


def keygen(directory: Path) -> None:
    directory.mkdir(mode=0o700, parents=False, exist_ok=False)
    private = Ed25519PrivateKey.generate()
    write_new(directory / "signing.key", private.private_bytes_raw())
    write_new(directory / "verify.pub", private.public_key().public_bytes_raw())
    print(f"Created {directory / 'signing.key'}")
    print(f"Created {directory / 'verify.pub'}")


def read_raw_key(path: Path) -> bytes:
    data = path.read_bytes()
    if len(data) != 32:
        raise UltraError(f"{path.name} must contain exactly 32 raw bytes")
    return data


def sign_manifest(manifest_bytes: bytes, signing_key: Path) -> bytes:
    private = Ed25519PrivateKey.from_private_bytes(read_raw_key(signing_key))
    return private.sign(manifest_bytes)


def verify_manifest_signature(manifest_bytes: bytes, signature: bytes, public_key: Path) -> None:
    if len(signature) != 64:
        raise UltraError("invalid Ed25519 signature length")
    public = Ed25519PublicKey.from_public_bytes(read_raw_key(public_key))
    try:
        public.verify(signature, manifest_bytes)
    except InvalidSignature as exc:
        raise UltraError("manifest signature invalid") from exc


def pad_to_size(path: Path, target: int) -> None:
    current = path.stat().st_size
    if current > target:
        raise UltraError(
            f"protected output ({current}) exceeds original size ({target}); "
            "cannot preserve exact size"
        )
    remaining = target - current
    if remaining == 0:
        return
    with path.open("ab", buffering=0) as out:
        while remaining:
            take = min(remaining, 1024 * 1024)
            out.write(secrets.token_bytes(take))
            remaining -= take
        os.fsync(out.fileno())


def run_packer(packer: Path, source: Path, output: Path) -> None:
    if not packer.is_file():
        raise UltraError(f"packer not found: {packer}")
    command = [
        str(packer),
        "--parallax-ultra-lib",
        "-o",
        str(output),
        str(source),
    ]
    proc = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if proc.returncode != 0:
        raise UltraError("native packer failed:\n" + proc.stdout[-8000:])
    if not output.is_file() or output.stat().st_size <= 0:
        raise UltraError("native packer produced no output")


def protect(args: argparse.Namespace) -> None:
    source = Path(args.input).resolve(strict=True)
    output = Path(args.output).absolute()
    packer = Path(args.packer).resolve(strict=True)
    signing_key = None if args.unsigned_dev else Path(args.signing_key).resolve(strict=True)

    if output.exists() or output.is_symlink():
        raise UltraError("output already exists")
    if source == output:
        raise UltraError("input and output must differ")

    source_info = inspect_arm64_shared_elf(source)
    source_size = source.stat().st_size
    source_sha = sha256_file(source)
    packer_sha = sha256_file(packer)

    output.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{output.name}.", suffix=".pvm4.tmp", dir=output.parent)
    os.close(fd)
    temp = Path(temp_name)
    try:
        temp.unlink()
        run_packer(packer, source, temp)
        protected_info = inspect_arm64_shared_elf(temp)

        if args.preserve_size:
            pad_to_size(temp, source_size)
            # Padding must not affect the ELF program-header policy.
            protected_info = inspect_arm64_shared_elf(temp)

        protected_size = temp.stat().st_size
        protected_sha = sha256_file(temp)
        if protected_sha == source_sha:
            raise UltraError("protected output is byte-identical to input")

        # Atomic publish into a path that was required not to exist.
        os.rename(temp, output)

        manifest = {
            "schema": SCHEMA,
            "profile": PROFILE,
            "created_utc": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
            "input": {
                "name": source.name,
                "size": source_size,
                "sha256": source_sha,
                "elf": source_info,
            },
            "output": {
                "name": output.name,
                "size": protected_size,
                "sha256": protected_sha,
                "elf": protected_info,
                "same_size_as_input": protected_size == source_size,
            },
            "packer": {
                "name": packer.name,
                "sha256": packer_sha,
            },
            "protection": {
                "pvm4_transport_layers": 4,
                "pvm4_lane_orders": 4,
                "per_file_program_id": True,
                "per_block_lane_tag": True,
                "standard_restore_command_exposed": False,
                "whole_payload_plaintext_disk_restore": False,
                "runtime_model": "block-local PVM4 decode then native decompression",
            },
        }
        manifest_bytes = (
            json.dumps(manifest, sort_keys=True, indent=2, separators=(",", ": "))
            + "\n"
        ).encode("utf-8")
        manifest_path = output.with_suffix(output.suffix + ".pvm.json")
        write_new(manifest_path, manifest_bytes)

        if signing_key is not None:
            signature = sign_manifest(manifest_bytes, signing_key)
            sig_path = output.with_suffix(output.suffix + ".pvm.sig")
            write_new(sig_path, signature)
            print(f"Signed manifest: {sig_path}")
        else:
            print("WARNING: unsigned development mode; provenance is not authenticated")

        print(f"Protected: {output}")
        print(f"Profile  : {PROFILE}")
        print(f"Input    : {source_size} bytes")
        print(f"Output   : {protected_size} bytes")
        print(f"SHA-256  : {protected_sha}")
        print(f"Manifest : {manifest_path}")
    finally:
        try:
            temp.unlink()
        except FileNotFoundError:
            pass


def verify(args: argparse.Namespace) -> None:
    artifact = Path(args.artifact).resolve(strict=True)
    manifest_path = Path(args.manifest or (str(artifact) + ".pvm.json")).resolve(strict=True)
    manifest_bytes = manifest_path.read_bytes()
    if len(manifest_bytes) > 1024 * 1024:
        raise UltraError("manifest too large")
    manifest = json.loads(manifest_bytes)
    if manifest.get("schema") != SCHEMA or manifest.get("profile") != PROFILE:
        raise UltraError("unsupported protection manifest")

    expected = manifest.get("output", {})
    if expected.get("size") != artifact.stat().st_size:
        raise UltraError("artifact size mismatch")
    if expected.get("sha256") != sha256_file(artifact):
        raise UltraError("artifact SHA-256 mismatch")
    inspect_arm64_shared_elf(artifact)

    if args.public_key:
        signature_path = Path(args.signature or (str(artifact) + ".pvm.sig")).resolve(strict=True)
        verify_manifest_signature(
            manifest_bytes, signature_path.read_bytes(), Path(args.public_key).resolve(strict=True)
        )
        print("Manifest signature: VALID")
    elif args.require_signature:
        raise UltraError("--require-signature needs --public-key")

    print(f"Artifact verified: {artifact}")
    print(f"Profile: {PROFILE}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="parallax-ultra")
    sub = parser.add_subparsers(dest="command", required=True)

    keys = sub.add_parser("keygen", help="create a new Ed25519 provenance keypair")
    keys.add_argument("directory")

    p = sub.add_parser("protect", help="protect one Android ARM64 shared library")
    p.add_argument("input")
    p.add_argument("output")
    p.add_argument("--packer", required=True, help="fresh CI-built ParallaxLibPacker binary")
    p.add_argument("--signing-key", help="32-byte raw Ed25519 private key")
    p.add_argument("--unsigned-dev", action="store_true", help="explicitly allow unsigned dev output")
    p.add_argument("--no-preserve-size", dest="preserve_size", action="store_false")
    p.set_defaults(preserve_size=True)

    v = sub.add_parser("verify", help="verify artifact, manifest and optional signature")
    v.add_argument("artifact")
    v.add_argument("--manifest")
    v.add_argument("--public-key")
    v.add_argument("--signature")
    v.add_argument("--require-signature", action="store_true")

    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "keygen":
            keygen(Path(args.directory))
        elif args.command == "protect":
            if not args.unsigned_dev and not args.signing_key:
                raise UltraError("production protection requires --signing-key (or explicit --unsigned-dev)")
            protect(args)
        else:
            verify(args)
        return 0
    except (OSError, ValueError, UltraError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
