"""Base class shared by all enrichers.

An enricher takes one IOC and returns an Enrichment. The base class handles the
cross-cutting concerns so each concrete enricher only implements the live lookup:

  - applicability: does this enricher handle this IOC type at all?
  - offline / no-key short-circuit -> a clear "not queried" Enrichment
  - cache read/write
  - rate-limit and network-error handling -> an Enrichment carrying an error,
    never an exception that crashes the pipeline
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

import requests

from soc_automation.cache import Cache
from soc_automation.config import Config
from soc_automation.models import IOC, Enrichment, IOCType

DEFAULT_TIMEOUT = 10


class Enricher(ABC):
    #: which IOC types this enricher can handle
    handles: tuple[IOCType, ...] = ()
    #: the config key attribute name (e.g. "abuseipdb_key"), or None if keyless
    key_attr: str | None = None

    name: str = "enricher"

    def __init__(self, config: Config, cache: Cache, session: requests.Session | None = None):
        self.config = config
        self.cache = cache
        self.session = session or requests.Session()

    # --- lifecycle ------------------------------------------------------- #
    def applies_to(self, ioc: IOC) -> bool:
        return ioc.type in self.handles

    def _key(self) -> str | None:
        return getattr(self.config, self.key_attr) if self.key_attr else None

    def enrich(self, ioc: IOC) -> Enrichment:
        """Enrich one IOC, going through cache and offline/error handling."""
        if not self.applies_to(ioc):
            return self._skip(ioc, "not applicable to this IOC type")

        cache_key = f"{self.name}:{ioc}"
        cached = self.cache.get(cache_key)
        if cached is not None:
            return _from_cache(self.name, ioc, cached)

        if self.key_attr and not self.config.can_query(self._key()):
            reason = "offline mode" if self.config.offline else "no API key configured"
            return self._skip(ioc, f"not queried ({reason})")

        try:
            enrichment = self._query_live(ioc)
        except requests.HTTPError as exc:
            status = exc.response.status_code if exc.response is not None else None
            msg = "rate limited (HTTP 429)" if status == 429 else f"HTTP error {status}"
            return self._error(ioc, msg)
        except requests.RequestException as exc:
            return self._error(ioc, f"network error: {exc.__class__.__name__}")

        self.cache.set(cache_key, _to_cache(enrichment))
        return enrichment

    # --- concrete enrichers implement this ------------------------------- #
    @abstractmethod
    def _query_live(self, ioc: IOC) -> Enrichment:
        """Perform the real API lookup for an IOC and return an Enrichment."""

    # --- helpers --------------------------------------------------------- #
    def _skip(self, ioc: IOC, summary: str) -> Enrichment:
        return Enrichment(self.name, ioc, malicious=False, score=0, summary=summary)

    def _error(self, ioc: IOC, message: str) -> Enrichment:
        return Enrichment(self.name, ioc, malicious=False, score=0, summary=message, error=message)


def _to_cache(e: Enrichment) -> dict[str, Any]:
    return {
        "malicious": e.malicious,
        "score": e.score,
        "summary": e.summary,
        "details": e.details,
        "error": e.error,
    }


def _from_cache(source: str, ioc: IOC, d: dict[str, Any]) -> Enrichment:
    return Enrichment(
        source=source,
        ioc=ioc,
        malicious=bool(d.get("malicious", False)),
        score=int(d.get("score", 0)),
        summary=str(d.get("summary", "")) + " (cached)",
        details=d.get("details", {}),
        error=d.get("error"),
    )
