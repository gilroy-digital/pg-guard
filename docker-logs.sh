#!/usr/bin/env bash

CONTAINER="pg_guard"

echo "--------------------------------------"
echo "pg_guard log utility"
echo "--------------------------------------"

if ! docker ps --format '{{.Names}}' | grep -q "^${CONTAINER}$"; then
    echo "pg_guard container is not running."
    exit 1
fi

if [ "$1" = "follow" ]; then
    echo "Tailing pg_guard logs..."
    echo "--------------------------------------"
    docker logs -f $CONTAINER
    exit 0
fi

if [ "$1" = "recent" ]; then
    echo "Last 100 log lines:"
    echo "--------------------------------------"
    docker logs --tail 100 $CONTAINER
    exit 0
fi

echo "Container status:"
docker ps --filter "name=$CONTAINER"

echo ""
echo "Recent logs:"
echo "--------------------------------------"
docker logs --tail 50 $CONTAINER

echo ""
echo "Usage:"
echo "./docker-logs.sh follow   # tail logs"
echo "./docker-logs.sh recent   # last 100 lines"