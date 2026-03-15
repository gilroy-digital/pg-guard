#!/usr/bin/env bash
set -e

set -a
source .env.registry
set +a

if [ -z "$GHCR_USER" ] || [ -z "$GHCR_TOKEN" ]; then
    echo "Set GHCR_USER and GHCR_TOKEN in .env.registry"
    exit 1
fi

echo "$GHCR_TOKEN" | docker login ghcr.io -u "$GHCR_USER" --password-stdin

docker build -t "$IMAGE" .
docker push "$IMAGE"

echo "Pushed $IMAGE"
