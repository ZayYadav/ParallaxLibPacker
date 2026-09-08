#!/usr/bin/env bash
set -euo pipefail
umask 077

SOURCE_DIR="${1:-upx-devel}"
TARGET="$SOURCE_DIR/src/stub/arm64-linux.elf-so_fold.h"
STUBTOOLS_URL="https://github.com/upx/upx-stubtools/releases/download/v20221212/bin-upx-20221212.tar.xz"
STUBTOOLS_DIR="${RUNNER_TEMP:-/tmp}/parallax-upx-stubtools"
ARCHIVE="$STUBTOOLS_DIR/bin-upx-20221212.tar.xz"

[[ -d "$SOURCE_DIR/src/stub" ]] || {
  echo "ERROR: source directory not found: $SOURCE_DIR" >&2
  exit 1
}

mkdir -p "$STUBTOOLS_DIR"
if [[ ! -f "$ARCHIVE" ]]; then
  curl --fail --location --retry 3 --proto '=https' --tlsv1.2     "$STUBTOOLS_URL" -o "$ARCHIVE"
fi

echo "509e06639118a79d8e79489a400e134c6d3ca36bad2c6ec29648d7c1e5b81afa  $ARCHIVE" | sha256sum -c -

# Old UPX cross compiler needs libmpfr.so.4. The CI workflow installs libmpfr6;
# use the compatibility symlink recommended by upstream for stub rebuilding.
if [[ ! -e /usr/lib/x86_64-linux-gnu/libmpfr.so.4 && -e /usr/lib/x86_64-linux-gnu/libmpfr.so.6 ]]; then
  sudo ln -s /usr/lib/x86_64-linux-gnu/libmpfr.so.6     /usr/lib/x86_64-linux-gnu/libmpfr.so.4
fi

if [[ ! -d "$STUBTOOLS_DIR/bin-upx-20221212" ]]; then
  tar -xJf "$ARCHIVE" -C "$STUBTOOLS_DIR"
fi
export PATH="$STUBTOOLS_DIR/bin-upx-20221212:$PATH"

mkdir -p "$SOURCE_DIR/src/stub/tmp"

for tool in arm64-linux-gcc-4.9.2 arm64-linux-ld-2.25 arm64-linux-objcopy-2.25; do
  command -v "$tool" >/dev/null 2>&1 || {
    echo "ERROR: UPX stub tool missing: $tool" >&2
    exit 1
  }
done

# Force regeneration from the active ELF-SO source. Deliberately do NOT touch
# src/stub/src/arm64-linux.shlib-init.S; that file is outside this hardening path.
rm -f "$TARGET"
rm -f "$SOURCE_DIR/src/stub/tmp/arm64-linux.elf-so_main.o"
rm -f "$SOURCE_DIR/src/stub/tmp/arm64-linux.elf-so_main.d"
rm -f "$SOURCE_DIR/src/stub/tmp/arm64-linux.elf-so_fold.o"
rm -f "$SOURCE_DIR/src/stub/tmp/arm64-linux.elf-so_fold.d"

make -C "$SOURCE_DIR/src/stub" arm64-linux.elf-so_fold.h

[[ -s "$TARGET" ]] || {
  echo "ERROR: regenerated ARM64 ELF-SO stub header is missing" >&2
  exit 1
}
grep -q 'STUB_ARM64_LINUX_ELF_SO_FOLD_SIZE' "$TARGET" || {
  echo "ERROR: regenerated stub header has unexpected format" >&2
  exit 1
}

# The committed header predates PVM4, therefore CI should observe a generated
# delta. If it does not, the modified runtime source was not compiled in.
if git diff --quiet -- "$TARGET"; then
  echo "ERROR: ARM64 ELF-SO stub did not change after PVM4 regeneration" >&2
  exit 1
fi

if ! git diff --quiet -- "$SOURCE_DIR/src/stub/src/arm64-linux.shlib-init.S"; then
  echo "ERROR: forbidden arm64-linux.shlib-init.S changed" >&2
  exit 1
fi

echo "Regenerated hardened ARM64 ELF-SO runtime stub:"
grep -E 'STUB_ARM64_LINUX_ELF_SO_FOLD_(SIZE|ADLER32|CRC32)' "$TARGET"
