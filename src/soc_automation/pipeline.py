"""The alert -> enrich -> score -> respond pipeline."""

from __future__ import annotations

from pathlib import Path

import requests

from soc_automation.cache import Cache
from soc_automation.config import Config
from soc_automation.enrichment import Enricher, default_enrichers
from soc_automation.extract import extract_iocs
from soc_automation.models import Alert, Enrichment, PipelineResult
from soc_automation.response import respond
from soc_automation.scoring import score_alert


class Pipeline:
    """Orchestrates the four stages for a single alert."""

    def __init__(
        self,
        config: Config | None = None,
        enrichers: list[Enricher] | None = None,
        tickets_dir: Path | None = None,
    ) -> None:
        self.config = config or Config.load()
        if enrichers is not None:
            self.enrichers = enrichers
        else:
            cache = Cache(self.config.cache_dir)
            self.enrichers = default_enrichers(self.config, cache, requests.Session())
        self.tickets_dir = tickets_dir

    def run(self, alert: Alert) -> PipelineResult:
        iocs = extract_iocs(alert)

        enrichments: list[Enrichment] = []
        for ioc in iocs:
            for enricher in self.enrichers:
                if enricher.applies_to(ioc):
                    enrichments.append(enricher.enrich(ioc))

        verdict = score_alert(alert, enrichments)
        response = respond(alert, iocs, enrichments, verdict, tickets_dir=self.tickets_dir)
        return PipelineResult(
            alert=alert,
            iocs=iocs,
            enrichments=enrichments,
            verdict=verdict,
            response=response,
        )
