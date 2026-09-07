#!/usr/bin/env python3
"""Signed, encrypted distribution packages. Does not execute or load libraries."""

import argparse
import os
from pathlib import Path
import struct
import sys

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


MAGIC = b"PLPKG\x00\x01\x00"
HEADER = struct.Struct(">8sQ12s")
MAX_INPUT = 128 * 1024 * 1024
OVERHEAD = HEADER.size + 16 + 64


def read_bounded(path, limit):
    with open(path, "rb") as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError(f"file exceeds {limit} byte limit")
    return data


def read_key(path):
    data = read_bounded(path, 32)
    if len(data) != 32:
        raise ValueError("key must contain exactly 32 raw bytes")
    return data


def write_new(path, data):
    """Never overwrite existing paths; remove incomplete output on write failure.

    The destination directory must be trusted and writable only by its owner.
    POSIX mode is owner-only; Windows requires an owner-restricted directory ACL.
    """
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        os.unlink(path)
        raise


def generate_keys(directory):
    directory = Path(directory)
    directory.mkdir(mode=0o700, parents=False, exist_ok=False)
    private = Ed25519PrivateKey.generate()
    write_new(directory / "signing.key", private.private_bytes_raw())
    write_new(directory / "verify.pub", private.public_key().public_bytes_raw())
    write_new(directory / "encryption.key", AESGCM.generate_key(bit_length=256))


def seal(source, output, encryption_key, signing_key):
    data = read_bounded(source, MAX_INPUT)
    if not data:
        raise ValueError("empty input is not supported")
    key = read_key(encryption_key)
    signer = Ed25519PrivateKey.from_private_bytes(read_key(signing_key))
    nonce = os.urandom(12)
    header = HEADER.pack(MAGIC, len(data), nonce)
    body = header + AESGCM(key).encrypt(nonce, data, header)
    write_new(output, body + signer.sign(body))


def verified_package(package, public_key):
    data = read_bounded(package, MAX_INPUT + OVERHEAD)
    if len(data) < OVERHEAD + 1:
        raise ValueError("truncated package")
    magic, size, nonce = HEADER.unpack(data[:HEADER.size])
    if magic != MAGIC or not 1 <= size <= MAX_INPUT:
        raise ValueError("unsupported format or invalid size")
    if len(data) != size + OVERHEAD:
        raise ValueError("package length mismatch")
    verifier = Ed25519PublicKey.from_public_bytes(read_key(public_key))
    verifier.verify(data[-64:], data[:-64])
    return data, nonce, size


def restore(package, output, encryption_key, public_key):
    # Verify and decrypt the same buffer; never reopen the package after verification.
    data, nonce, size = verified_package(package, public_key)
    plaintext = AESGCM(read_key(encryption_key)).decrypt(
        nonce, data[HEADER.size:-64], data[:HEADER.size]
    )
    if len(plaintext) != size:
        raise ValueError("plaintext length mismatch")
    # No plaintext file is created until both authentication checks pass.
    write_new(output, plaintext)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    keys = commands.add_parser("keygen", help="create a NEW private key directory")
    keys.add_argument("--directory", required=True)
    pack = commands.add_parser("seal", help="encrypt and sign a distribution file")
    pack.add_argument("input")
    pack.add_argument("output")
    pack.add_argument("--encryption-key", required=True)
    pack.add_argument("--signing-key", required=True)
    verify = commands.add_parser("verify", help="verify signature with a trusted public key")
    verify.add_argument("package")
    verify.add_argument("--public-key", required=True)
    unpack = commands.add_parser("restore", help="verify and decrypt to a NEW file")
    unpack.add_argument("package")
    unpack.add_argument("output")
    unpack.add_argument("--encryption-key", required=True)
    unpack.add_argument("--public-key", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "keygen":
            generate_keys(args.directory)
        elif args.command == "seal":
            seal(args.input, args.output, args.encryption_key, args.signing_key)
        elif args.command == "verify":
            _, _, size = verified_package(args.package, args.public_key)
            print(f"Signature valid; payload size: {size} bytes")
        else:
            restore(args.package, args.output, args.encryption_key, args.public_key)
    except (InvalidSignature, InvalidTag):
        print("ERROR: authentication failed (wrong key or modified package)", file=sys.stderr)
        return 1
    except (OSError, ValueError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
