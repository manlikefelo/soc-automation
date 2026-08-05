"""Enrichment sources and a helper to build the default set."""

from __future__ import annotations

import requests

from soc_automation.cache import Cache
from soc_automation.config import Config
from soc_automation.enrichment.abuseipdb import AbuseIPDBEnricher
from soc_automation.enrichment.base import Enricher
from soc_automation.enrichment.geoip import GeoIPEnricher
from soc_automation.enrichment.virustotal import VirusTotalEnricher
from soc_automation.enrichment.whois import WhoisEnricher

__all__ = [
    "AbuseIPDBEnricher",
    "Enricher",
    "GeoIPEnricher",
    "VirusTotalEnricher",
    "WhoisEnricher",
    "default_enrichers",
]


def default_enrichers(
    config: Config, cache: Cache, session: requests.Session | None = None
) -> list[Enricher]:
    """The standard enrichment set: reputation (AbuseIPDB, VT) + context (GeoIP, WHOIS)."""
    shared = session or requests.Session()
    return [
        AbuseIPDBEnricher(config, cache, shared),
        VirusTotalEnricher(config, cache, shared),
        GeoIPEnricher(config, cache, shared),
        WhoisEnricher(config, cache, shared),
    ]
