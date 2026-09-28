#!/usr/bin/env bash
# Read-only security scan of a git repo with throwaway Docker containers:
# gitleaks (full history), Semgrep, Trivy, zizmor. Nothing is installed or uploaded.
#
# Usage: bash scan.sh <repo> [--ref origin/main] [--out DIR] [--keep]
#   <repo>   path to a git checkout
#   --ref    what to scan (default origin/main, falls back to HEAD); scanned from `git archive`,
#            so uncommitted work and gitignored files are never touched
#   --out    where JSON/text results go (default $TMPDIR/readiness-scan/<repo>)
#   --keep   keep the export copy under ~/.cache/readiness-test/<repo>
set -euo pipefail
exec 3>&2  # fd 3 = the terminal, so progress never lands in a tool's redirected output

REPO="" REF="origin/main" OUT="" KEEP=0
while [ $# -gt 0 ]; do
  case $1 in
    --ref)  REF=$2; shift 2 ;;
    --out)  OUT=$2; shift 2 ;;
    --keep) KEEP=1; shift ;;
    -h|--help) sed -n '2,10p' "$0"; exit 0 ;;
    *) REPO=$1; shift ;;
  esac
done
[ -n "$REPO" ] || { echo "usage: scan.sh <repo> [--ref R] [--out DIR] [--keep]" >&2; exit 2; }
REPO=$(cd "$REPO" && pwd)
NAME=$(basename "$REPO")
OUT=${OUT:-${TMPDIR:-/tmp}/readiness-scan/$NAME}
HERE=$(cd "$(dirname "$0")" && pwd)

command -v docker >/dev/null && docker info >/dev/null 2>&1 || { echo "docker is not running" >&2; exit 1; }
git -C "$REPO" rev-parse --git-dir >/dev/null 2>&1 || { echo "$REPO is not a git repo" >&2; exit 1; }

git -C "$REPO" fetch --quiet origin 2>/dev/null || true
git -C "$REPO" rev-parse --verify --quiet "$REF" >/dev/null || { echo "ref $REF not found, using HEAD" >&2; REF=HEAD; }

# Docker may only mount paths under $HOME (not /tmp) on some setups, so the export lives there.
WORK=$HOME/.cache/readiness-test/$NAME
rm -rf "$WORK"; mkdir -p "$WORK" "$OUT"
[ "$KEEP" = 1 ] || trap 'rm -rf "$WORK"' EXIT
git -C "$REPO" archive "$REF" | tar -x -C "$WORK"
echo "scanning $NAME @ $(git -C "$REPO" rev-parse --short "$REF") -> $OUT" >&3

# Semgrep language packs from what the tree contains
packs="--config p/owasp-top-ten --config p/secrets"
found() { find "$WORK" -maxdepth 3 \( -name node_modules -o -name vendor \) -prune -o -name "$1" -print -quit | grep -q .; }
found composer.json && packs="$packs --config p/php"
found go.mod        && packs="$packs --config p/golang"
if found package.json; then
  packs="$packs --config p/javascript --config p/typescript"
  grep -rqs '"next"' --include=package.json "$WORK" && packs="$packs --config p/nextjs"
fi
echo "semgrep packs:${packs//--config /}" >&3

ME=$(id -u):$(id -g)
# A failing tool must not stop the others: note it and move on.
step() { local name=$1; shift; echo "  $name ..." >&3; "$@" || echo "  ($name failed with $?; see $OUT/$name.log)" >&3; }

# Whole history, so this one mounts the real repo (read-only). --redact keeps secret values out of the output.
step gitleaks docker run --rm --user "$ME" -v "$REPO":/repo:ro zricethezav/gitleaks:latest detect \
  --source /repo --log-opts=--all --redact --no-banner --exit-code 0 --report-format json --report-path - \
  > "$OUT/gitleaks.json" 2> "$OUT/gitleaks.log"

# shellcheck disable=SC2086  # $packs is a list of flags on purpose
step semgrep docker run --rm --user "$ME" -e HOME=/tmp -v "$WORK":/src:ro semgrep/semgrep:latest semgrep scan \
  $packs --metrics=off --json --quiet --exclude node_modules --exclude vendor --exclude '*.min.js' /src \
  > "$OUT/semgrep.json" 2> "$OUT/semgrep.log"

step trivy docker run --rm -v readiness-trivy-cache:/root/.cache -v "$WORK":/src:ro aquasec/trivy:latest fs \
  --scanners vuln,secret,misconfig --severity HIGH,CRITICAL --format json --quiet /src \
  > "$OUT/trivy.json" 2> "$OUT/trivy.log"

if [ -d "$WORK/.github" ]; then
  echo "  zizmor ..." >&3
  # exit codes 10-14 mean "findings", not failure
  docker run --rm -v "$WORK":/w:ro -w /w ghcr.io/zizmorcore/zizmor:latest --offline --format plain . \
    > "$OUT/zizmor.txt" 2>&1 || [ $? -ge 10 ] || echo "  (zizmor failed; see $OUT/zizmor.txt)" >&3
fi

python3 "$HERE/summarize.py" "$OUT"
