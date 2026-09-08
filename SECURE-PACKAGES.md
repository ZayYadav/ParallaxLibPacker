# Legacy signed/encrypted distribution packages

For runtime Android ARM64 shared-library protection, use the canonical flow in README.md.

scripts/parallax_package.py implements a portable distribution container using AES-256-GCM and Ed25519. A .plpkg is **not a loadable shared library**, and authorized restoration deliberately recovers its original payload.

Because of that property, do not use .plpkg when the requirement is to protect a loadable shared library without restoring the original file to disk. Use scripts/parallax_ultra.py protect instead.

## Legacy package commands

~~~sh
python -m pip install -r scripts/requirements-secure.txt

python scripts/parallax_package.py keygen --directory private-keys

python scripts/parallax_package.py seal input.bin package.plpkg \
  --encryption-key private-keys/encryption.key \
  --signing-key private-keys/signing.key

python scripts/parallax_package.py verify package.plpkg \
  --public-key private-keys/verify.pub

python scripts/parallax_package.py restore package.plpkg restored.bin \
  --encryption-key private-keys/encryption.key \
  --public-key private-keys/verify.pub
~~~

These commands are retained for encrypted release transport, backups, and installer workflows. They are not aliases for PVM4.

## Runtime protector commands

~~~sh
python scripts/parallax_ultra.py keygen ./parallax-keys

python scripts/parallax_ultra.py protect libOriginal.so libProtected.so \
  --packer /path/to/parallax_linux \
  --signing-key ./parallax-keys/signing.key

python scripts/parallax_ultra.py verify libProtected.so \
  --public-key ./parallax-keys/verify.pub \
  --require-signature
~~~

Low-level:

~~~sh
parallax_linux --parallax-ultra-lib -o libProtected.so libOriginal.so
~~~

There is no PVM4 restore command. Public native -d, --decompress, and --uncompress are disabled in the hardened fork.

## Legacy container properties

The .plpkg format uses AES-256-GCM, fresh random nonces, Ed25519 signatures, strict length validation, and owner-only POSIX file defaults where supported.

Keep private encryption/signing keys outside the repository. The legacy package format does not prevent memory inspection after authorized restoration. PVM4 and .plpkg solve different problems.
