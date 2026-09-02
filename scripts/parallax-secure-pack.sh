#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  PARALLAX_PACKER=/path/to/ParallaxLibPacker ./scripts/parallax-secure-pack.sh input.so output.so

Defaults:
  PARALLAX_PACKER=./parallax_linux

This wrapper performs defensive ELF checks, packs an Android shared library,
validates the packed result, and writes a SHA-256 integrity manifest.
EOF
}

if [[ $# -ne 2 ]]; then
  usage
  exit 2
fi

PACKER="${PARALLAX_PACKER:-./parallax_linux}"
INPUT="$1"
OUTPUT="$2"
MANIFEST="${OUTPUT}.sha256"
INFO="${OUTPUT}.integrity.txt"

for tool in file readelf sha256sum stat; do
  command -v "$tool" >/dev/null 2>&1 || {
    echo "ERROR: required tool not found: $tool" >&2
    exit 1
  }
done

[[ -f "$INPUT" ]] || {
  echo "ERROR: input file does not exist: $INPUT" >&2
  exit 1
}

[[ -x "$PACKER" ]] || {
  echo "ERROR: packer is not executable: $PACKER" >&2
  exit 1
}

if ! file "$INPUT" | grep -q 'ELF'; then
  echo "ERROR: input is not an ELF file" >&2
  exit 1
fi

if ! readelf -h "$INPUT" | grep -q 'DYN (Shared object file)'; then
  echo "ERROR: input is not an ELF shared object (.so)" >&2
  exit 1
fi

echo '[1/5] Checking ELF memory permissions...'
if readelf -lW "$INPUT" | grep -E 'LOAD.*RWE' >/dev/null; then
  echo 'ERROR: input contains a writable+executable LOAD segment (RWX)' >&2
  exit 1
fi

if readelf -lW "$INPUT" | grep GNU_STACK | grep -q 'RWE'; then
  echo 'ERROR: input requests an executable stack' >&2
  exit 1
fi

echo '[2/5] Checking common linker hardening...'
RELRO=no
NOW=no
if readelf -lW "$INPUT" | grep -q GNU_RELRO; then
  RELRO=yes
else
  echo 'WARNING: GNU_RELRO not present'
fi

if readelf -dW "$INPUT" 2>/dev/null | grep -Eq 'BIND_NOW|FLAGS.*NOW'; then
  NOW=yes
else
  echo 'WARNING: immediate binding (BIND_NOW) not present'
fi

INPUT_SIZE=$(stat -c%s "$INPUT")
INPUT_SHA=$(sha256sum "$INPUT" | awk '{print $1}')

mkdir -p "$(dirname "$OUTPUT")"
rm -f "$OUTPUT" "$MANIFEST" "$INFO"

echo '[3/5] Packing Android shared library...'
"$PACKER" --android-shlib --best --lzma -o "$OUTPUT" "$INPUT"

[[ -s "$OUTPUT" ]] || {
  echo 'ERROR: packer did not produce output' >&2
  exit 1
}

echo '[4/5] Validating packed file...'
"$PACKER" -t "$OUTPUT"

OUTPUT_SIZE=$(stat -c%s "$OUTPUT")
OUTPUT_SHA=$(sha256sum "$OUTPUT" | awk '{print $1}')

printf '%s  %s\n' "$OUTPUT_SHA" "$(basename "$OUTPUT")" > "$MANIFEST"

cat > "$INFO" <<EOF
ParallaxLibPacker integrity manifest
input=$(basename "$INPUT")
input_size=$INPUT_SIZE
input_sha256=$INPUT_SHA
output=$(basename "$OUTPUT")
output_size=$OUTPUT_SIZE
output_sha256=$OUTPUT_SHA
input_relro=$RELRO
input_bind_now=$NOW
input_rwx_load=no
input_exec_stack=no
EOF

echo '[5/5] Done.'
echo "Input : $INPUT_SIZE bytes"
echo "Output: $OUTPUT_SIZE bytes"
if [[ "$INPUT_SIZE" -gt 0 ]]; then
  awk -v a="$OUTPUT_SIZE" -v b="$INPUT_SIZE" 'BEGIN { printf "Ratio : %.2f%%\n", (a/b)*100 }'
fi
echo "SHA256: $OUTPUT_SHA"
echo "Manifest: $MANIFEST"
echo "Info: $INFO"
