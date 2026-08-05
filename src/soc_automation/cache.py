"""A tiny on-disk JSON cache for enrichment results.

Reputation lookups are slow and rate-limited, and the same IOC recurs across
alerts. Caching keeps repeated enrichment fast and stays well within free-tier
limits. The cache is keyed by "<source>:<ioc>" and is safe to delete anytime.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class Cache:
    def __init__(self, cache_dir: Path) -> None:
        self.path = cache_dir / "enrichment.cache.json"
        self._data: dict[str, Any] = {}
        self._loaded = False

    def _load(self) -> None:
        if self._loaded:
            return
        if self.path.exists():
            try:
                self._data = json.loads(self.path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                self._data = {}  # a corrupt cache is not fatal; start fresh
        self._loaded = True

    def get(self, key: str) -> dict[str, Any] | None:
        self._load()
        value = self._data.get(key)
        return value if isinstance(value, dict) else None

    def set(self, key: str, value: dict[str, Any]) -> None:
        self._load()
        self._data[key] = value
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self._data, indent=2), encoding="utf-8")


class NullCache(Cache):
    """A cache that stores nothing - used in tests to keep them hermetic."""

    def __init__(self) -> None:  # noqa: D107
        self.path = Path("/dev/null")
        self._data = {}
        self._loaded = True

    def get(self, key: str) -> dict[str, Any] | None:
        return None

    def set(self, key: str, value: dict[str, Any]) -> None:
        return None
