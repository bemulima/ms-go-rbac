# Native macOS development

RBAC runs as a macOS process while Docker supplies only the shared PostgreSQL
and NATS dependencies. The application still receives its normal `DB_DSN`,
`NATS_URL`, and `HTTP_ADDR` configuration; no host address is embedded in Go
application code.

## Start shared infrastructure

From the infrastructure repository:

```sh
make native-infra-up
make native-infra-check
```

This starts the shared PostgreSQL and NATS endpoints on `127.0.0.1:5432` and
`127.0.0.1:4222`. It does not start RBAC or any other application service.

## Run RBAC natively

From this repository:

```sh
task migrate:native
task run:native
```

The native migration task applies the schema profile and canonical reference
roles without fixed principal assignments. Use
`task migrate-native-legacy-fixtures` only for an environment that explicitly
requires the historical assignments from migration 002.

The tasks read the approved infrastructure dotenv file at
`../../learning-platform-infrastructure/.env` by default. Set
`LW_INFRA_ENV_FILE` when that file is elsewhere. The adapter derives the
`lw_rbac` role DSN without printing its password and sets these native values:

| Setting | Default |
| --- | --- |
| database | `lw_rbac` |
| PostgreSQL | `127.0.0.1:5432` |
| NATS | `nats://127.0.0.1:4222` |
| HTTP | `127.0.0.1:18080` |

Use `RBAC_NATIVE_HTTP_PORT`, `RBAC_NATIVE_HTTP_ADDR`,
`RBAC_NATIVE_POSTGRES_HOST`, `RBAC_NATIVE_POSTGRES_PORT`,
`RBAC_NATIVE_NATS_URL`, or `RBAC_NATIVE_DB_DSN` only to override the native
adapter. Keep secrets in the approved local infrastructure dotenv file.

Stop the native RBAC process with `Ctrl-C`. Stop shared dependencies without
deleting their volumes or networks with `make native-infra-down` in the
infrastructure repository.

## Docker Compose path

Docker mode remains self contained:

```sh
task up
task migrate-up
```

Compose resolves PostgreSQL and NATS through the container DNS names
`postgres` and `nats`. The migration task invokes the same
`ms-rbac-migrate` binary as the native task. Stop this repository's containers
with `task down`.
