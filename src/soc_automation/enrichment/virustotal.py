"""VirusTotal file-hash reputation enrichment (free public API)."""

from __future__ import annotations

from soc_automation.enrichment.base import DEFAULT_TIMEOUT, Enricher
from soc_automation.models import IOC, Enrichment, IOCType

API_URL = "https://www.virustotal.com/api/v3/files/{hash}"


class VirusTotalEnricher(Enricher):
    name = "virustotal"
    handles = (IOCType.HASH,)
    key_attr = "virustotal_key"

    def _query_live(self, ioc: IOC) -> Enrichment:
        resp = self.session.get(
            API_URL.format(hash=ioc.value),
            headers={"x-apikey": self._key() or ""},
            timeout=DEFAULT_TIMEOUT,
        )
        resp.raise_for_status()
        attrs = resp.json().get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        malicious_count = int(stats.get("malicious", 0))
        total = sum(int(v) for v in stats.values()) or 1
        # Score scales with how many engines flagged it, capped at 100.
        score = min(100, round(malicious_count / total * 100) + (50 if malicious_count else 0))
        return Enrichment(
            source=self.name,
            ioc=ioc,
            malicious=malicious_count > 0,
            score=min(100, score),
            summary=f"{malicious_count}/{total} engines flagged this hash",
            details={
                "malicious": malicious_count,
                "suspicious": int(stats.get("suspicious", 0)),
                "harmless": int(stats.get("harmless", 0)),
                "meaningful_name": attrs.get("meaningful_name"),
            },
        )
