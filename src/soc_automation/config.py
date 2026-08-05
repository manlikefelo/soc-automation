"""Runtime configuration, read from environment / .env.

Offline-first by design: the lab's alerts use private IPs that public reputation
services cannot score, and the test suite must run with no keys and no network.
A source is only queried live when its key is present AND offline mode is off.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

_TRUTHY = {"1", "true", "yes", "on"}


@dataclass
class Config:
    abuseipdb_key: str | None
    virustotal_key: str | None
    offline: bool
    cache_dir: Path

    @classmethod
    def load(cls, *, env_file: str | None = ".env") -> Config:
        if env_file and Path(env_file).exists():
            load_dotenv(env_file)
        offline_raw = os.getenv("SOC_OFFLINE")
        # Default is offline unless the user explicitly sets SOC_OFFLINE to a
        # falsey value - keeps accidental network calls (and cost) from happening.
        offline = True if offline_raw is None else offline_raw.strip().lower() in _TRUTHY
        return cls(
            abuseipdb_key=os.getenv("ABUSEIPDB_API_KEY") or None,
            virustotal_key=os.getenv("VIRUSTOTAL_API_KEY") or None,
            offline=offline,
            cache_dir=Path(os.getenv("SOC_CACHE_DIR", ".cache")),
        )

    def can_query(self, key: str | None) -> bool:
        """A live query is allowed only when not offline and the key is set."""
        return not self.offline and bool(key)
