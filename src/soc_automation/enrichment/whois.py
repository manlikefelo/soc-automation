"""WHOIS/RDAP context enrichment for IPs and domains (free, no key required).

Uses RDAP over HTTPS (the modern, JSON WHOIS) so there's no need for a raw WHOIS
socket client or a paid API. Context only - it reports the registered network /
domain owner, which helps an analyst judge whether a source is expected.
"""

from __future__ import annotations

from typing import Any

from soc_automation.enrichment.base import DEFAULT_TIMEOUT, Enricher
from soc_automation.extract import is_public_ip
from soc_automation.models import IOC, Enrichment, IOCType

IP_RDAP_URL = "https://rdap.org/ip/{value}"
DOMAIN_RDAP_URL = "https://rdap.org/domain/{value}"


class WhoisEnricher(Enricher):
    name = "whois"
    handles = (IOCType.IP, IOCType.DOMAIN)
    key_attr = None

    def enrich(self, ioc: IOC) -> Enrichment:
        if ioc.type is IOCType.IP and not is_public_ip(ioc.value):
            return self._skip(ioc, "private/lab IP - no public registration")
        if self.config.offline:
            return self._skip(ioc, "not queried (offline mode)")
        return super().enrich(ioc)

    def _query_live(self, ioc: IOC) -> Enrichment:
        url = (IP_RDAP_URL if ioc.type is IOCType.IP else DOMAIN_RDAP_URL).format(value=ioc.value)
        resp = self.session.get(url, timeout=DEFAULT_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
        name = data.get("name") or data.get("ldhName") or "unknown"
        entities = data.get("entities", [])
        registrar = _first_entity_name(entities)
        return Enrichment(
            source=self.name,
            ioc=ioc,
            malicious=False,
            score=0,  # context only
            summary=f"registered to {registrar or name}",
            details={
                "name": name,
                "registrar": registrar,
                "handle": data.get("handle"),
                "country": data.get("country"),
            },
        )


def _first_entity_name(entities: list[Any]) -> str | None:
    for ent in entities:
        if not isinstance(ent, dict):
            continue
        vcard = ent.get("vcardArray")
        if isinstance(vcard, list) and len(vcard) > 1:
            for item in vcard[1]:
                if isinstance(item, list) and item and item[0] == "fn":
                    return str(item[-1])
        if ent.get("handle"):
            return str(ent["handle"])
    return None
