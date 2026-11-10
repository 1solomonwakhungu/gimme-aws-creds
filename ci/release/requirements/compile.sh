#!/usr/bin/env sh
# Regenerate the hash-locked release tooling requirements from the *.in files.
# Review the resulting diff like any other code change before committing it.
# EXCLUDE_NEWER enforces a cooldown so newly published releases are not adopted
# before the community has had time to notice a compromised upload.
set -eu
cd "$(dirname "$0")"
EXCLUDE_NEWER="${EXCLUDE_NEWER:?set EXCLUDE_NEWER to an RFC 3339 timestamp at least 14 days in the past}"
compile() {
  uv pip compile --quiet --universal --generate-hashes --python-version 3.10 \
    --exclude-newer "$EXCLUDE_NEWER" --index-url https://pypi.org/simple \
    --custom-compile-command "EXCLUDE_NEWER=$EXCLUDE_NEWER ci/release/requirements/compile.sh" \
    "$@"
}
compile build.in -o build.txt
compile check.in -o check.txt
compile audit.in -o audit.txt
compile unit.in -o unit.txt \
  --no-emit-package requests --no-emit-package urllib3 --no-emit-package certifi \
  --no-emit-package idna --no-emit-package charset-normalizer --no-emit-package pyyaml
