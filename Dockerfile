FROM rust:1.88-slim AS builder

WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    postgresql-client docker.io \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/pg_guard /usr/local/bin/pg_guard
COPY --from=builder /app/target/release/pg_browse /usr/local/bin/pg_browse
COPY --from=builder /app/target/release/pg_recall /usr/local/bin/pg_recall
COPY --from=builder /app/target/release/pg_web /usr/local/bin/pg_web

EXPOSE 3690

CMD ["pg_web", "/backups"]