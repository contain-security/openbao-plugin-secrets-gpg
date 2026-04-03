#!/usr/bin/env bash
set -euo pipefail

VERSION=${1:-dev}
BINARY=openbao-plugin-secrets-gpg

echo "Building version: $VERSION"

mkdir -p dist

for GOOS in linux darwin; do
    for GOARCH in amd64 arm64; do
        OUT="${BINARY}_${VERSION}_${GOOS}_${GOARCH}"
        echo "  -> $OUT"
        GOOS=$GOOS GOARCH=$GOARCH CGO_ENABLED=0 go build \
            -ldflags="-X main.version=${VERSION}" \
            -o "dist/${OUT}" .
        sha256sum "dist/${OUT}" > "dist/${OUT}.sha256"
    done
done

echo "Done. Binaries in dist/"
