# pg_guard

A Docker container that automatically backs up all running Postgres instances to a specified target directory at midnight daily.

## Usage

Create a `docker-compose.yml` file:

```yaml


services:
  pg_guard:
    build: .
    container_name: pg_guard
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - ./backups:/backups
    environment:
      - PG_KEEP_RUNS=14
    restart: unless-stopped
```

Then run:

```bash
docker-compose up -d
```

Or set environment variables:

```bash
export PG_KEEP_RUNS=14
docker-compose up -d
```

The container will run continuously and execute backups at midnight (00:00) every day.

## Configuration

Set the following environment variables in your `docker-compose.yml` or export them:

- `PG_KEEP_RUNS`: Number of backup runs to keep per Postgres container (default: 14)

Credentials are automatically read from each container's `POSTGRES_USER` and `POSTGRES_PASSWORD` environment variables.

## What it does

- Discovers all running Docker containers with images containing "postgres"
- Automatically reads `POSTGRES_USER` and `POSTGRES_PASSWORD` from each container's environment
- Runs `pg_dumpall` inside each container and compresses with gzip
- Saves the backup as `YYYY-MM-DD.sql.gz` in the `/backups/<container_name>/` directory
- Keeps only the specified number of recent backups, deleting older ones

## Requirements

- Docker socket mounted for container discovery
- Postgres instances must allow connections from the backup container (same Docker network)
- `PGPASSWORD` environment variable set if authentication is required
- Target directory mounted as a volume

## Assumptions

- Postgres containers have `POSTGRES_USER` and `POSTGRES_PASSWORD` environment variables set
- The specified user has superuser privileges for `pg_dumpall`
- Containers have `gzip` available for compression
- Docker socket is accessible for container inspection and execution
