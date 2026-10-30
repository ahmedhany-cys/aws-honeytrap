#!/usr/bin/env bash
# Build build/lambda.zip: the honeytrap package + Lambda handlers.
# No third-party dependencies are bundled - the engine uses the standard
# library, and boto3 is provided by the python3.12 Lambda runtime.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
STAGE="$ROOT/build/lambda"
rm -rf "$STAGE" "$ROOT/build/lambda.zip"
mkdir -p "$STAGE"
cp -R "$ROOT/backend/honeytrap" "$STAGE/honeytrap"
cp -R "$ROOT/lambda/handlers" "$STAGE/handlers"
find "$STAGE" -name "__pycache__" -type d -prune -exec rm -rf {} +
# Reproducible archive: fixed timestamps and sorted entries -> stable source_code_hash.
find "$STAGE" -exec touch -t 202601010000 {} +
(cd "$STAGE" && find . -type f | LC_ALL=C sort | zip -X -q "$ROOT/build/lambda.zip" -@)
echo "built build/lambda.zip ($(du -h "$ROOT/build/lambda.zip" | cut -f1))"
