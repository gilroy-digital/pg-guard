# PG-Guard

A lightweight Postgres backup manager and database inspector. Runs as a single Docker container, auto-discovers your Postgres instances, and provides both a web dashboard and CLI tools.

## Quick Start

```bash
docker run -d \
  --name pg-guard \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v pg-guard-data:/backups \
  -p 3690:3690 \
  --restart unless-stopped \
  ghcr.io/gilroy-digital/pg-guard:latest
```

That's it. Open `http://localhost:3690` — on first visit you'll create an admin account.

### Using Docker Compose

If you prefer, create a `docker-compose.yml`:

```yaml
services:
  pg_guard:
    image: ghcr.io/gilroy-digital/pg-guard:latest
    container_name: pg_guard
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - pg-guard-data:/backups
    ports:
      - "3690:3690"
    restart: unless-stopped

volumes:
  pg-guard-data:
```

```bash
docker compose up -d
```

## Web Dashboard

The dashboard at port `3690` provides:

- **Backup management** — view, create, and restore backups for all detected Postgres containers
- **Backup All Now** — one-click backup of every Postgres container
- **Per-container backup** — backup individual containers on demand
- **Browse backups** — view tables and paginated row data from any backup file
- **Restore** — drop and recreate databases from a selected backup (with confirmation)
- **Live database inspector** — browse running databases, tables, columns, and row data in real time
- **Table search** — filter tables by name or column name
- **Column inspector** — inspect table schemas (column names, types, nullable) from the table list
- **Row detail panel** — click any row to view all fields as key-value pairs
- **Full-text search** — search across all columns in a live table (server-side SQL query with pagination)
- **Page filter** — instant client-side filtering of the current page of results
- **Configurable schedule** — set backup frequency (hourly to weekly), start time, and retention from the UI
- **Toggle backups** — enable/disable automatic backups without removing the container
- **Dark/light mode** — retro-tech theme with a toggle, defaults to dark
- **Authentication** — Argon2id password hashing, session cookies, login required

## CLI Tools

All CLI tools are available inside the container via `docker exec`:

| Command | Description |
|---|---|
| `docker exec pg-guard pg_guard /backups` | Back up all Postgres containers |
| `docker exec pg-guard pg_guard /backups --container <name>` | Back up a single container |
| `docker exec -it pg-guard pg_browse /backups` | Browse backup contents interactively |
| `docker exec -it pg-guard pg_recall /backups` | Restore a backup interactively |

## How It Works

- Auto-discovers running Postgres containers via the Docker socket
- Reads `POSTGRES_USER` and `POSTGRES_PASSWORD` from each container's environment
- Backups use `pg_dumpall --clean` and are stored as timestamped gzipped SQL files
- Restores terminate connections, drop all application databases, then replay the full dump
- Configuration and credentials are stored in the named Docker volume
- Login passwords are hashed with Argon2id — only the hash is stored

## Requirements

- Docker socket mounted (`/var/run/docker.sock`)
- Postgres containers must have `POSTGRES_USER` and `POSTGRES_PASSWORD` environment variables set
- The specified user needs superuser privileges for `pg_dumpall`

## Support PG-Guard

PG-Guard is free, open source software built and maintained by an independent developer. If it saves you time or keeps your data safe, consider supporting its development:

[**Donate**](https://donate.stripe.com/fZu6oHbg026l7EIax2fbq04)

[More tools from Gilroy.Digital](https://gilroy.digital/tools)

---

Built by **Fleebee**
