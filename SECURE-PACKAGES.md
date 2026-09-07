# Signed, encrypted distribution packages

`scripts/parallax_package.py` adds AES-256-GCM encryption and Ed25519 signatures
for distribution/storage of libraries or other release artifacts. The existing
Linux executable and UPX loader are unchanged. This tool never executes input.

The new commands are `keygen`, `seal`, `verify`, and `restore`. A `.plpkg` is a
distribution container, **not a loadable `.so`**. Your trusted installer must
restore the library before normal platform loading. Existing APKs/loaders do
not automatically understand this format.

## Setup and commands

Run from the repository root, with Python 3.10 or newer:

```sh
python -m venv .venv
# Linux:
. .venv/bin/activate
# Windows PowerShell instead:
# .\.venv\Scripts\Activate.ps1
python -m pip install -r scripts/requirements-secure.txt

python scripts/parallax_package.py keygen --directory private-keys

python scripts/parallax_package.py seal libDARK.so library.plpkg --encryption-key private-keys/encryption.key --signing-key private-keys/signing.key

python scripts/parallax_package.py verify library.plpkg --public-key private-keys/verify.pub

python scripts/parallax_package.py restore library.plpkg restored.so --encryption-key private-keys/encryption.key --public-key private-keys/verify.pub

python -m unittest discover -s tests -v
```

The example operates on the library bytes directly. `seal` also accepts an
already-produced release artifact. It does not invoke the bundled packer.
Output paths must not already exist; there is no destructive overwrite flag.
Commands return nonzero on failure. Keep output directories private and do not
let another process consume an output before the command succeeds.

## Trust and key handling

- Keep `signing.key` on the release signing machine, outside the repository and
  application. Distribute `verify.pub` through a trusted channel and pin it in
  your installer. Accepting a public key from the package/download defeats trust.
- Keep `encryption.key` separate from the package. Anyone holding this key can
  decrypt it. Do not embed it in the APK or treat client-side storage as a secret
  against the device owner. This example provides no key distribution service.
- Keys are raw 32-byte files. POSIX files are created with mode 0600 and the key
  directory with 0700. On Windows, use a directory with an owner-restricted ACL;
  POSIX permission bits do not enforce equivalent Windows access controls.
- Each seal uses a fresh random 96-bit nonce. Rotate encryption keys regularly;
  do not use one key indefinitely across high-volume releases. Keep encrypted
  backups of signing keys and define revocation/rotation in your release process.
- `verify` authenticates the signed package only. `restore` additionally checks
  the GCM tag before creating plaintext output. Neither proves the payload is
  safe code or prevents replay of an older signed release. Version/rollback
  policy must be enforced by a trusted installer or server.

## Format v1 and limits

The signed body is an exact byte sequence: 8-byte magic/version
`50 4c 50 4b 47 00 01 00`, unsigned 64-bit big-endian plaintext length,
12-byte random nonce, then ciphertext including its 16-byte GCM tag.
A 64-byte Ed25519 signature over that entire body follows. The first 28 bytes
are GCM associated data. The verification key is never read from the package.

Inputs must be nonempty and at most 128 MiB. Strict length checks reject trailing
data, truncation, unknown formats and oversized input. Processing buffers the
artifact in memory and needs several times its size in RAM. This is ordinary
file encryption, not in-memory execution or an anti-analysis loader.

There is no compression layer to decompress. Authorized decryption deliberately
recovers the original bytes. After restoration/execution, this format does not
prevent copying, memory inspection, hooking or patching. For native hardening
and server-side authorization, see `android-hardening/README.md`.

Cryptographic API references:
[AES-GCM](https://cryptography.io/en/latest/hazmat/primitives/aead/),
[Ed25519](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ed25519/).
