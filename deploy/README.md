# Deployment

This directory contains the Docker Compose, Dockerfile, Caddy, and environment files for deploying `bt-log` and its witness.

Run the commands below from the repository root.

For the log, only the [Tessera POSIX](https://github.com/transparency-dev/tessera/tree/main/storage/posix) backend is supported.

You'll need to pick a storage backend for the witness. SQLite, PostgreSQL, and MySQL are supported.

Docker Compose values can be customized by copying `deploy/.env.example` to `deploy/.env` and editing it before generating keys:

```shell
cp deploy/.env.example deploy/.env
```

The most important values to customize are `LOG_ORIGIN` and `WITNESS_ORIGIN`, because they become part of the signed log and witness identities. You can also customize `BT_LOG_PORT`, `WITNESS_PORT`, `READONLY_PROXY_LOCAL_PORT`, and `READONLY_PROXY_SITE`.

Use this Compose invocation throughout:

```shell
docker compose --env-file deploy/.env -f deploy/docker-compose.yml ...
```

If you do not need custom values, omit `--env-file deploy/.env`.

The log and witness ports are bound to `127.0.0.1` by default. This keeps `/add` and `/admin/bulk/append` reachable from the host for local ingestion, but prevents direct access from the network.

If you want to expose the log publicly, run the optional read-only proxy instead of exposing `BT_LOG_PORT`. The read-only proxy blocks `/add` and `/admin/*`, and proxies browser/status, checkpoint, and tile requests to the log. Caddy certificate state is stored in Docker volumes so automatically issued certificates survive container recreation.

For direct public HTTPS on a domain, set `READONLY_PROXY_SITE` to the domain name, point DNS at the host, and publish container ports 80 and 443 for the read-only proxy with a local Compose override. Do not publish `BT_LOG_PORT`, because that exposes `/add` and `/admin/bulk/append`.

Before running any backend profile, generate the log and witness keys once using the administrative commands in the backend section below. For example, with SQLite, run the SQLite administrative commands first, then start SQLite with the read-only proxy:

```shell
docker compose --env-file deploy/.env -f deploy/docker-compose.yml --profile sqlite --profile readonly-proxy up --wait
```

Then expose the read-only proxy port, for example:

```shell
tailscale funnel ${READONLY_PROXY_LOCAL_PORT:-8088}
```

Do not funnel `BT_LOG_PORT`, because that would expose `/add` and `/admin/bulk/append`.

## SQLite

Run the following administrative jobs once to generate the log and witness keys. The `up --wait` command below initializes the witness database from the generated log public key:

```shell
docker compose --env-file deploy/.env -f deploy/docker-compose.yml --profile admin --profile sqlite build
docker compose --env-file deploy/.env -f deploy/docker-compose.yml run gen-key-log
docker compose --env-file deploy/.env -f deploy/docker-compose.yml run gen-key-witness
```

Run the log and witness:

```shell
docker compose --env-file deploy/.env -f deploy/docker-compose.yml --profile sqlite up --wait
```

To clean up containers and volumes:

```shell
docker compose --env-file deploy/.env -f deploy/docker-compose.yml --profile sqlite down --remove-orphans --volumes
```

## PostgreSQL

Run the following administrative jobs once to generate the log and witness keys. The `up --wait` command below initializes the witness database from the generated log public key:

```shell
docker compose --env-file deploy/.env -f deploy/docker-compose.yml --profile admin --profile postgres build
docker compose --env-file deploy/.env -f deploy/docker-compose.yml run gen-key-log
docker compose --env-file deploy/.env -f deploy/docker-compose.yml run gen-key-witness
```

Run the log and witness:

```shell
docker compose --env-file deploy/.env -f deploy/docker-compose.yml --profile postgres up --wait
```

To clean up containers and volumes:

```shell
docker compose --env-file deploy/.env -f deploy/docker-compose.yml --profile postgres down --remove-orphans --volumes
```

## MySQL

Run the following administrative jobs once to generate the log and witness keys. The `up --wait` command below initializes the witness database from the generated log public key:

```shell
docker compose --env-file deploy/.env -f deploy/docker-compose.yml --profile admin --profile mysql build
docker compose --env-file deploy/.env -f deploy/docker-compose.yml run gen-key-log
docker compose --env-file deploy/.env -f deploy/docker-compose.yml run gen-key-witness
```

Run the log and witness:

```shell
docker compose --env-file deploy/.env -f deploy/docker-compose.yml --profile mysql up --wait
```

To clean up containers and volumes:

```shell
docker compose --env-file deploy/.env -f deploy/docker-compose.yml --profile mysql down --remove-orphans --volumes
```
