"""Loads config.toml (path from NETINV_CONFIG, default ./config.toml). Secrets can come from env vars."""
from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Settings:
    database_url: str = "postgresql+psycopg://netinv:netinv@localhost:5432/netinv"
    ingest_token: str = ""                 # required header X-Ingest-Token for /api/ingest/* (future agent)
    ui_user: str = ""                      # optional HTTP basic auth for the dashboard/API
    ui_password: str = ""
    ad: dict = field(default_factory=dict)
    winrm: dict = field(default_factory=dict)
    snmp: dict = field(default_factory=dict)
    schedule: dict = field(default_factory=dict)
    insights: dict = field(default_factory=dict)
    outdated_software: list = field(default_factory=list)
    update: dict = field(default_factory=dict)


def _env(value: str) -> str:
    """Allow 'env:VARNAME' in config so passwords stay out of the file."""
    if isinstance(value, str) and value.startswith("env:"):
        return os.environ.get(value[4:], "")
    return value


def _resolve(obj):
    if isinstance(obj, dict):
        return {k: _resolve(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_resolve(v) for v in obj]
    return _env(obj)


def load_settings() -> Settings:
    path = Path(os.environ.get("NETINV_CONFIG", "config.toml"))
    data = _resolve(tomllib.loads(path.read_text())) if path.exists() else {}
    s = Settings()
    s.database_url = os.environ.get("DATABASE_URL") or data.get("database", {}).get("url", s.database_url)
    srv = data.get("server", {})
    s.ingest_token = srv.get("ingest_token", "")
    s.ui_user = srv.get("ui_user", "")
    s.ui_password = srv.get("ui_password", "")
    for key in ("ad", "winrm", "snmp", "schedule", "insights", "update"):
        setattr(s, key, data.get(key, {}))
    s.outdated_software = data.get("outdated_software", [])
    return s


settings = load_settings()
