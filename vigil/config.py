"""Configuration loader for Vigil Security."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml


@dataclass
class TelegramConfig:
    bot_token: str = ""
    chat_id: str = ""
    enabled: bool = False


@dataclass
class DependencyScanConfig:
    enabled: bool = True
    paths: list[str] = field(default_factory=list)


@dataclass
class SecretScanConfig:
    enabled: bool = True
    paths: list[str] = field(default_factory=list)
    exclude_patterns: list[str] = field(default_factory=lambda: [
        "*.pyc", "__pycache__", ".git", "node_modules", ".venv",
        "venv", "*.min.js", "*.min.css", "*.lock", "package-lock.json",
    ])
    max_file_size_kb: int = 512


@dataclass
class PortScanConfig:
    enabled: bool = True
    hosts: list[str] = field(default_factory=list)
    ports: list[int] = field(default_factory=lambda: [
        21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587,
        993, 995, 3306, 3389, 5432, 6379, 8080, 8443, 9200, 27017,
    ])
    timeout: float = 2.0


@dataclass
class SSLConfig:
    enabled: bool = True
    hosts: list[str] = field(default_factory=list)
    warn_days: int = 30
    critical_days: int = 7


@dataclass
class UptimeConfig:
    enabled: bool = True
    endpoints: list[dict] = field(default_factory=list)
    timeout: float = 10.0
    expected_status: int = 200


@dataclass
class VigilConfig:
    telegram: TelegramConfig = field(default_factory=TelegramConfig)
    dependencies: DependencyScanConfig = field(default_factory=DependencyScanConfig)
    secrets: SecretScanConfig = field(default_factory=SecretScanConfig)
    ports: PortScanConfig = field(default_factory=PortScanConfig)
    ssl: SSLConfig = field(default_factory=SSLConfig)
    uptime: UptimeConfig = field(default_factory=UptimeConfig)
    output_dir: str = "./vigil-reports"


def _env_substitute(value: str) -> str:
    """Replace ${ENV_VAR} patterns with environment variable values."""
    if not isinstance(value, str):
        return value
    import re
    pattern = re.compile(r"\$\{([^}]+)\}")
    def replacer(match: re.Match) -> str:
        env_var = match.group(1)
        env_val = os.environ.get(env_var, "")
        return env_val
    return pattern.sub(replacer, value)


def _process_env_vars(data: dict | list | str) -> dict | list | str:
    """Recursively substitute environment variables in config data."""
    if isinstance(data, dict):
        return {k: _process_env_vars(v) for k, v in data.items()}
    if isinstance(data, list):
        return [_process_env_vars(item) for item in data]
    if isinstance(data, str):
        return _env_substitute(data)
    return data


def load_config(path: Optional[str] = None) -> VigilConfig:
    """Load configuration from a YAML file.

    If no path is provided, searches for vigil.yaml or vigil.yml
    in the current directory.
    """
    if path is None:
        for name in ("vigil.yaml", "vigil.yml"):
            if Path(name).exists():
                path = name
                break

    if path is None or not Path(path).exists():
        return VigilConfig()

    with open(path) as f:
        raw = yaml.safe_load(f)

    if not raw:
        return VigilConfig()

    raw = _process_env_vars(raw)
    config = VigilConfig()

    # Telegram
    if "telegram" in raw:
        tg = raw["telegram"]
        config.telegram = TelegramConfig(
            bot_token=tg.get("bot_token", ""),
            chat_id=str(tg.get("chat_id", "")),
            enabled=tg.get("enabled", bool(tg.get("bot_token"))),
        )

    # Dependencies
    if "dependencies" in raw:
        dep = raw["dependencies"]
        config.dependencies = DependencyScanConfig(
            enabled=dep.get("enabled", True),
            paths=dep.get("paths", []),
        )

    # Secrets
    if "secrets" in raw:
        sec = raw["secrets"]
        config.secrets = SecretScanConfig(
            enabled=sec.get("enabled", True),
            paths=sec.get("paths", []),
            exclude_patterns=sec.get("exclude_patterns", config.secrets.exclude_patterns),
            max_file_size_kb=sec.get("max_file_size_kb", 512),
        )

    # Ports
    if "ports" in raw:
        p = raw["ports"]
        config.ports = PortScanConfig(
            enabled=p.get("enabled", True),
            hosts=p.get("hosts", []),
            ports=p.get("ports", config.ports.ports),
            timeout=p.get("timeout", 2.0),
        )

    # SSL
    if "ssl" in raw:
        s = raw["ssl"]
        config.ssl = SSLConfig(
            enabled=s.get("enabled", True),
            hosts=s.get("hosts", []),
            warn_days=s.get("warn_days", 30),
            critical_days=s.get("critical_days", 7),
        )

    # Uptime
    if "uptime" in raw:
        u = raw["uptime"]
        config.uptime = UptimeConfig(
            enabled=u.get("enabled", True),
            endpoints=u.get("endpoints", []),
            timeout=u.get("timeout", 10.0),
            expected_status=u.get("expected_status", 200),
        )

    if "output_dir" in raw:
        config.output_dir = raw["output_dir"]

    return config
