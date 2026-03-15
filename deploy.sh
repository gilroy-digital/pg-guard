#!/usr/bin/env bash
docker compose down --rmi local && docker compose up -d --build
