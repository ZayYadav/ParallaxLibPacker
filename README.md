# ParallaxLibPacker — Ultra ARM64 Library Protection

Parallax Ultra is the hardened client-side protection profile for Android ARM64 shared libraries.

The canonical profile is **PVM4 ARM64 v2**. The protected artifact on disk is not a normal UPX-compatible compressed stream, and the runtime loader does not write the original shared library back to disk.

> Scope: client-side protection only. A protected library may continue to use its own HTTPS/API/server endpoints normally. Parallax Ultra does not rewrite, proxy, block, or depend on those network requests.

## Security model

For ARM64 Android shared libraries, the hardened path provides:

- strict ELF64 little-endian AArch64 / ET_DYN validation;
- rejection of RWX PT_LOAD segments and executable GNU stack;
- PVM4 four-stage compressed-block transport virtualization;
- four execution-order dialects selected per block;
- per-file randomized program id;
- per-block lane/tag diversification;
- block-local runtime decode instead of restoring a plaintext library file;
- zeroization of transient PVM4 transport buffers after use;
- public -d, --decompress and --uncompress restore commands disabled;
- startup LD_PRELOAD detection;
- TracerPid debugger/tracer detection;
- conservative /proc/self/maps checks for strong injection-framework markers;
- AArch64 strlen GOT relocation verification against executable libc mapping;
- conservative inline-hook detection when strlen begins with an unconditional branch that escapes executable libc;
- optional exact input-size preservation;
- SHA-256 artifact provenance;
- optional Ed25519-signed protection manifest;
- fail-closed production frontend.

Detection deliberately does **not** treat root/Magisk alone as an attack, does not probe Frida TCP ports, and does not modify TLS, sockets, DNS, HTTP clients, certificates, or endpoint strings. This keeps libraries with their own API/server traffic compatible.

Threat response is non-destructive: a strong runtime hook/tamper signal terminates loading. It does not erase user data, fill storage, corrupt files, or damage the device.

The file upx-devel/src/stub/src/arm64-linux.shlib-init.S is intentionally outside this hardening work and is not modified by the Ultra profile.

## Recommended commands

### 1. Install frontend dependency

~~~sh
python -m pip install -r scripts/requirements-secure.txt
~~~

### 2. Generate an Ed25519 provenance key

~~~sh
python scripts/parallax_ultra.py keygen ./parallax-keys
~~~

Keep parallax-keys/signing.key private and outside source control.

### 3. Protect an ARM64 Android library

Use a **fresh CI-built packer artifact**.

Linux:

~~~sh
python scripts/parallax_ultra.py protect libOriginal.so libProtected.so \
  --packer /path/to/parallax_linux \
  --signing-key ./parallax-keys/signing.key
~~~

Windows:

~~~powershell
python scripts/parallax_ultra.py protect libOriginal.so libProtected.so `
  --packer .\ParallaxLibPacker-windows-x64.exe `
  --signing-key .\parallax-keys\signing.key
~~~

By default the frontend pads a smaller protected ELF with cryptographically random trailing bytes until its file size equals the original. If the protected ELF is larger than the original, exact-size mode fails instead of truncating data.

To allow a smaller output:

~~~sh
python scripts/parallax_ultra.py protect libOriginal.so libProtected.so \
  --packer /path/to/parallax_linux \
  --signing-key ./parallax-keys/signing.key \
  --no-preserve-size
~~~

### 4. Verify artifact and signed manifest

~~~sh
python scripts/parallax_ultra.py verify libProtected.so \
  --public-key ./parallax-keys/verify.pub \
  --require-signature
~~~

### 5. Shell wrapper

~~~sh
PARALLAX_PACKER=/path/to/parallax_linux \
PARALLAX_SIGNING_KEY=./parallax-keys/signing.key \
./scripts/parallax-secure-pack.sh libOriginal.so libProtected.so
~~~

Development-only unsigned output:

~~~sh
PARALLAX_PACKER=/path/to/parallax_linux \
PARALLAX_UNSIGNED_DEV=1 \
./scripts/parallax-secure-pack.sh libOriginal.so libProtected.so
~~~

### Low-level native command

~~~sh
parallax_linux --parallax-ultra-lib -o libProtected.so libOriginal.so
~~~

The old public Android selector and restore commands are not the Ultra interface:

~~~text
--android-shlib       removed from the public hardened interface
-d                    disabled
--decompress          disabled
--uncompress          disabled
~~~

There is deliberately no restore command for a PVM4-protected shared library.

## Runtime flow

~~~text
original ARM64 ELF
        |
        v
ELF validation + compression
        |
        v
PVM4 per-block lane selection
        |
        +--> stage A: stream transform
        +--> stage B: additive transform
        +--> stage C: bit-rotation transform
        +--> stage D: local permutation
        |
        v
non-standard protected block bytes on disk
        |
        v
loader startup hook checks
        |
        v
one private block copied + PVM4 inverse
        |
        v
native decompression into target PT_LOAD
        |
        v
transport block wiped
        |
        v
next block
~~~

The whole original shared library is not reconstructed as a filesystem file by the Ultra loader.

## Hook protection and API compatibility

The runtime checks are independent of the protected library's business logic. A protected library can still use libc/C++, JNI, OpenSSL/BoringSSL, curl, Java/Kotlin networking through JNI, and arbitrary HTTPS/API endpoints.

Parallax does not require a protection server and does not need to know the library's endpoint, API key format, or application protocol.

For strlen, the runtime verifies resolved AArch64 GOT/GLOB_DAT/JUMP_SLOT targets when such relocations exist. The target must remain inside executable libc. It also checks a conservative direct-branch case for an inline trampoline escaping libc. Libraries that do not import strlen skip this symbol-specific check.

## CI verification

The hardening branch verifies:

- PVM4 encode/decode vectors across lane tags;
- regeneration of the active ARM64 ELF-SO folded runtime;
- arm64-linux.shlib-init.S remains unchanged;
- Linux and Windows packer builds;
- RELRO / NX / no-RWX checks;
- a real AArch64 ET_DYN regression library importing strlen;
- actual protection with --parallax-ultra-lib;
- protected ELF policy checks;
- public -d restoration must fail;
- Python manifest/key/ELF-policy tests;
- SHA-256 build artifacts.

## Important limit

No client-side native protector can make extraction mathematically impossible against an attacker who fully controls a rooted device. CPU instructions that execute eventually exist in executable form in memory.

PVM4 raises the cost of static extraction and removes the simple standard-packer-to-original-file recovery path. It also reduces decoded transport lifetime and adds hook/tamper checks.

A future true function-level VM would require an ARM64 instruction lifter, custom IR, relocation/unwind/TLS support, and multiple interpreters. Current PVM4 is transport/runtime virtualization and is intentionally described accurately rather than as whole-program instruction virtualization.

## Legacy distribution packages

scripts/parallax_package.py and .plpkg are a separate signed/encrypted distribution format. They intentionally support authorized restoration and are not the runtime PVM4 protector.

See SECURE-PACKAGES.md.
