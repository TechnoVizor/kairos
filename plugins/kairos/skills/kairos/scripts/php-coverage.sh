#!/usr/bin/env bash
# PHP test coverage (pcov) in a throwaway container; host PHP rarely has a coverage driver or GD.
#
# Usage: bash php-coverage.sh <dir> [phpunit args...]
#   <dir>  an EXPORT of the project (git archive) that contains composer.json. The script runs
#          `composer install` into it, so never pass a working checkout. Must live under $HOME
#          (Docker file sharing). The DB is whatever phpunit.xml sets (normally sqlite :memory:).
set -euo pipefail

[ $# -ge 1 ] || { sed -n '2,7p' "$0" >&2; exit 2; }
DIR=$(cd "$1" && pwd); shift
HERE=$(cd "$(dirname "$0")" && pwd)
IMG=kairos-php:8.4

[ -f "$DIR/composer.json" ] || { echo "no composer.json in $DIR" >&2; exit 1; }
case $DIR in "$HOME"/*) ;; *) echo "warning: $DIR is outside \$HOME, Docker may refuse to mount it" >&2 ;; esac
if { ls "$DIR"/vite.config.* >/dev/null 2>&1; } && [ ! -f "$DIR/public/build/manifest.json" ]; then
  echo "note: Vite project without public/build/manifest.json; if view tests fail on the manifest, copy the build from a clean checkout at the same commit" >&2
fi

docker image inspect "$IMG" >/dev/null 2>&1 || docker build -q -t "$IMG" -f "$HERE/php-coverage.Dockerfile" "$HERE" >/dev/null
KEY="base64:$(head -c 32 /dev/urandom | base64)"  # throwaway APP_KEY; no .env is copied into the container

docker run --rm --user "$(id -u):$(id -g)" -e HOME=/tmp -e COMPOSER_HOME=/tmp/composer -e APP_KEY="$KEY" \
  -v "$DIR":/app -w /app "$IMG" bash -c '
    composer install --no-interaction --no-progress --no-scripts -q
    php -d pcov.enabled=1 -d memory_limit=1G vendor/bin/phpunit --coverage-text --colors=never "$@"
  ' _ "$@"
