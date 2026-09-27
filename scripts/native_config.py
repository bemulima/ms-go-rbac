#!/usr/bin/env python3
"""Run an RBAC command with native-development endpoints and local secrets."""

from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path
from urllib.parse import quote


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_INFRA_ENV_FILE = ROOT.parents[1] / "learning-platform-infrastructure" / ".env"
KEY = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def load_dotenv(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        key, separator, value = line.partition("=")
        if separator != "=" or not KEY.fullmatch(key.strip()):
            raise ValueError(f"unsupported dotenv syntax at {path}:{number}")
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        values[key.strip()] = value
    return values


def required(values: dict[str, str], name: str) -> str:
    value = values.get(name, "")
    if not value:
        raise ValueError(f"{name} is required by the approved infrastructure environment")
    return value


def native_environment() -> dict[str, str]:
    configured_path = os.environ.get("LW_INFRA_ENV_FILE")
    infra_env_file = Path(configured_path).expanduser() if configured_path else DEFAULT_INFRA_ENV_FILE
    values = load_dotenv(infra_env_file)
    # The infrastructure file owns shared credentials. Only explicit native
    # overrides may replace its values, so an unrelated legacy .env cannot
    # accidentally point a native process at the standalone Docker database.
    values.update({name: value for name, value in os.environ.items() if name.startswith("RBAC_NATIVE_")})

    database = values.get("RBAC_NATIVE_DATABASE", "lw_rbac")
    postgres_host = values.get("RBAC_NATIVE_POSTGRES_HOST", "127.0.0.1")
    postgres_port = values.get("RBAC_NATIVE_POSTGRES_PORT", "5432")
    native_port = values.get("RBAC_NATIVE_HTTP_PORT", "18080")
    db_dsn = values.get("RBAC_NATIVE_DB_DSN")
    if not db_dsn:
        db_user = values.get("LW_RBAC_DB_USER", "lw_rbac")
        db_password = values.get("LW_RBAC_DB_PASSWORD") or required(values, "LW_POSTGRES_PASSWORD")
        db_dsn = "postgres://{}:{}@{}:{}/{}?sslmode=disable".format(
            quote(db_user, safe=""), quote(db_password, safe=""), postgres_host, postgres_port, database
        )

    environment = dict(os.environ)
    environment.update(
        {
            "DB_DSN": db_dsn,
            "NATS_URL": values.get("RBAC_NATIVE_NATS_URL", "nats://127.0.0.1:4222"),
            "HTTP_ADDR": values.get("RBAC_NATIVE_HTTP_ADDR", f"127.0.0.1:{native_port}"),
        }
    )
    print(
        "native RBAC config: database={} postgres={}:{} nats={} http={}".format(
            database, postgres_host, postgres_port, environment["NATS_URL"], environment["HTTP_ADDR"]
        ),
        flush=True,
    )
    return environment


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        parser.error("a command is required after --")
    try:
        environment = native_environment()
    except (OSError, ValueError) as error:
        print(f"native RBAC configuration failed: {error}", file=sys.stderr)
        return 2
    os.execvpe(command[0], command, environment)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
