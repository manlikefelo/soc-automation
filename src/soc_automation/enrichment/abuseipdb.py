"""AbuseIPDB IP-reputation enrichment (free tier)."""

from __future__ import annotations

from soc_automation.enrichment.base import DEFAULT_TIMEOUT, Enricher
from soc_automation.extract import is_public_ip
from soc_automation.models import IOC, Enrichment, IOCType

API_URL = "https://api.abuseipdb.com/api/v2/check"


class AbuseIPDBEnricher(Enricher):
    name = "abuseipdb"
    handles = (IOCType.IP,)
    key_attr = "abuseipdb_key"

    def enrich(self, ioc: IOC) -> Enrichment:
        # A private/lab IP has no public reputation; short-circuit before any call.
        if ioc.type is IOCType.IP and not is_public_ip(ioc.value):
            return self._skip(ioc, "private/lab IP - no public reputation")
        return super().enrich(ioc)

    def _query_live(self, ioc: IOC) -> Enrichment:
        resp = self.session.get(
            API_URL,
            headers={"Key": self._key() or "", "Accept": "application/json"},
            params={"ipAddress": ioc.value, "maxAgeInDays": "90"},
            timeout=DEFAULT_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json().get("data", {})
        confidence = int(data.get("abuseConfidenceScore", 0))
        reports = int(data.get("totalReports", 0))
        malicious = confidence >= 50
        summary = f"abuse confidence {confidence}% over {reports} reports"
        return Enrichment(
            source=self.name,
            ioc=ioc,
            malicious=malicious,
            score=confidence,
            summary=summary,
            details={
                "abuseConfidenceScore": confidence,
                "totalReports": reports,
                "countryCode": data.get("countryCode"),
                "isp": data.get("isp"),
            },
        )
