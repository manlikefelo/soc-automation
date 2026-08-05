"""GeoIP context enrichment via ip-api.com (free, no key required).

This is a CONTEXT enricher: it never marks an IOC malicious on its own (location
isn't a verdict), but "auth failures from an unexpected country" is a useful
triage signal, so it contributes a small score for far-from-baseline geos.
"""

from __future__ import annotations

from soc_automation.enrichment.base import DEFAULT_TIMEOUT, Enricher
from soc_automation.extract import is_public_ip
from soc_automation.models import IOC, Enrichment, IOCType

API_URL = "http://ip-api.com/json/{ip}"


class GeoIPEnricher(Enricher):
    name = "geoip"
    handles = (IOCType.IP,)
    key_attr = None  # keyless service

    def enrich(self, ioc: IOC) -> Enrichment:
        if ioc.type is IOCType.IP and not is_public_ip(ioc.value):
            return self._skip(ioc, "private/lab IP - no geolocation")
        # keyless, but still respect offline mode
        if self.config.offline:
            return self._skip(ioc, "not queried (offline mode)")
        return super().enrich(ioc)

    def _query_live(self, ioc: IOC) -> Enrichment:
        resp = self.session.get(
            API_URL.format(ip=ioc.value),
            params={"fields": "status,country,countryCode,city,isp,as"},
            timeout=DEFAULT_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json()
        if data.get("status") != "success":
            return self._skip(ioc, "no geolocation available")
        country = data.get("country", "unknown")
        city = data.get("city", "")
        return Enrichment(
            source=self.name,
            ioc=ioc,
            malicious=False,
            score=0,  # context only
            summary=f"{city + ', ' if city else ''}{country} ({data.get('isp', 'unknown ISP')})",
            details={
                "country": country,
                "countryCode": data.get("countryCode"),
                "city": city,
                "isp": data.get("isp"),
                "as": data.get("as"),
            },
        )
