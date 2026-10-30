#!/usr/bin/env bash
# Build the Cowrie sensor image for the EC2 architecture and save it as
# build/cowrie-image.tar.gz. Terraform uploads it to the artifacts bucket and the
# instance loads it through the S3 gateway endpoint (it has no internet egress).
#
#   scripts/package_honeypot.sh            # linux/amd64 (t3.micro)
#   PLATFORM=linux/arm64 scripts/package_honeypot.sh   # t4g.micro
#
# Requires Docker (or a compatible engine). Without Docker locally, download the
# "cowrie-image" artifact produced by the CI workflow instead.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PLATFORM="${PLATFORM:-linux/amd64}"
mkdir -p "$ROOT/build"
docker build --platform "$PLATFORM" -f "$ROOT/honeypot/Dockerfile" -t honeytrap/cowrie:latest "$ROOT"
docker save honeytrap/cowrie:latest | gzip -9 > "$ROOT/build/cowrie-image.tar.gz"
echo "saved build/cowrie-image.tar.gz ($(du -h "$ROOT/build/cowrie-image.tar.gz" | cut -f1)) for $PLATFORM"
