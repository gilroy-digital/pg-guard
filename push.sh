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

# Container registry
echo ""
echo "=== Container Registry ==="
echo "$GHCR_TOKEN" | docker login ghcr.io -u "$GHCR_USER" --password-stdin
docker build -t "$IMAGE" .
docker push "$IMAGE"

echo ""
echo "Done — committed to git and pushed $IMAGE"
