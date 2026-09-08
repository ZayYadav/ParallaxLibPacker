#!/usr/bin/env bash
set -euo pipefail
umask 077

usage() {
  cat <<'EOF'
Usage:
  PARALLAX_PACKER=/path/to/fresh/parallax_linux \
  PARALLAX_SIGNING_KEY=/path/to/signing.key \
  ./scripts/parallax-secure-pack.sh input.so output.so

Development-only unsigned output:
  PARALLAX_PACKER=/path/to/fresh/parallax_linux \
  PARALLAX_UNSIGNED_DEV=1 \
  ./scripts/parallax-secure-pack.sh input.so output.so

The wrapper uses the hardened Parallax Ultra profile:
  - ARM64 ET_DYN only
  - PVM4 four-stage block diversification
  - public decompression command disabled
  - RWX / executable stack rejected
  - exact input-size preservation by default
  - atomic output
  - signed provenance manifest in production

Do not use a checked-in/stale packer binary. Use the latest successful
GitHub Actions artifact or an explicitly verified local build.
EOF
}

if [[ $# -ne 2 ]]; then
  usage
  exit 2
fi

PACKER="${PARALLAX_PACKER:-}"
SIGNING_KEY="${PARALLAX_SIGNING_KEY:-}"
UNSIGNED_DEV="${PARALLAX_UNSIGNED_DEV:-0}"

if [[ -z "$PACKER" ]]; then
  echo "ERROR: PARALLAX_PACKER is required; point it at a fresh verified build." >&2
  exit 1
fi

command -v python3 >/dev/null 2>&1 || {
  echo "ERROR: python3 is required." >&2
  exit 1
}

ARGS=(
  protect
  "$1"
  "$2"
  --packer "$PACKER"
)

if [[ "$UNSIGNED_DEV" == "1" ]]; then
  ARGS+=(--unsigned-dev)
else
  if [[ -z "$SIGNING_KEY" ]]; then
    echo "ERROR: PARALLAX_SIGNING_KEY is required for production protection." >&2
    echo "       Run: python3 scripts/parallax_ultra.py keygen ./parallax-keys" >&2
    exit 1
  fi
  ARGS+=(--signing-key "$SIGNING_KEY")
fi

exec python3 "$(dirname "$0")/parallax_ultra.py" "${ARGS[@]}"
