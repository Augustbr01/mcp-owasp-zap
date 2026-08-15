"""Configuração lida do ambiente."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from urllib.parse import urlparse


class ConfigError(RuntimeError):
    pass


@dataclass(frozen=True)
class Settings:
    base_url: str = "http://127.0.0.1:8080"
    api_key: str = ""
    timeout: float = 60.0
    allowed_hosts: tuple[str, ...] = field(default_factory=tuple)
    allow_active_scan: bool = True

    @classmethod
    def from_env(cls) -> "Settings":
        raw_hosts = os.environ.get("ZAP_ALLOWED_HOSTS", "").strip()
        hosts = tuple(h.strip().lower() for h in raw_hosts.split(",") if h.strip())
        return cls(
            base_url=os.environ.get("ZAP_BASE_URL", "http://127.0.0.1:8080").rstrip("/"),
            api_key=os.environ.get("ZAP_API_KEY", ""),
            timeout=float(os.environ.get("ZAP_TIMEOUT", "60")),
            allowed_hosts=hosts,
            allow_active_scan=os.environ.get("ZAP_ALLOW_ACTIVE_SCAN", "true").lower()
            not in {"0", "false", "no"},
        )

    def check_target(self, url: str) -> None:
        """Bloqueia alvos fora do allowlist (quando ZAP_ALLOWED_HOSTS está definido)."""
        if not self.allowed_hosts:
            return
        host = (urlparse(url).hostname or "").lower()
        if not host:
            raise ConfigError(f"URL inválida (sem host): {url!r}")
        for allowed in self.allowed_hosts:
            if host == allowed or (allowed.startswith(".") and host.endswith(allowed)):
                return
        raise ConfigError(
            f"Host {host!r} não está em ZAP_ALLOWED_HOSTS "
            f"({', '.join(self.allowed_hosts)}). Alvo recusado."
        )
