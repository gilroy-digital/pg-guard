#!/usr/bin/env bash
set -e

set -a
source .env.registry
set +a

if [ -z "$GHCR_USER" ] || [ -z "$GHCR_TOKEN" ]; then
    echo "Set GHCR_USER and GHCR_TOKEN in .env.registry"
    exit 1
fi

# Git commit
echo "=== Git ==="
git add -A
if git diff --cached --quiet; then
    echo "No changes to commit."
else
    read -p "Commit message: " MSG
    git commit -m "${MSG:-update}"
fi
git push origin "$(git branch --show-current)" 2>/dev/null || echo "No git remote configured, skipping push."

# Container registry (multi-arch)
echo ""
echo "=== Container Registry ==="
echo "$GHCR_TOKEN" | docker login ghcr.io -u "$GHCR_USER" --password-stdin

# Create builder if it doesn't exist
docker buildx inspect pg_guard_builder >/dev/null 2>&1 || \
    docker buildx create --name pg_guard_builder --use

docker buildx use pg_guard_builder
docker buildx build --platform linux/amd64,linux/arm64 -t "$IMAGE" --push .

echo ""
echo "Done — committed to git and pushed $IMAGE (amd64 + arm64)"
