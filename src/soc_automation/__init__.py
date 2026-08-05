"""soc-automation - automated alert enrichment, triage scoring, and response."""

from soc_automation.config import Config
from soc_automation.extract import extract_iocs
from soc_automation.models import (
    IOC,
    Action,
    Alert,
    Enrichment,
    IOCType,
    PipelineResult,
    Response,
    Verdict,
)
from soc_automation.pipeline import Pipeline
from soc_automation.scoring import score_alert

__version__ = "0.1.0"

__all__ = [
    "IOC",
    "Action",
    "Alert",
    "Config",
    "Enrichment",
    "IOCType",
    "Pipeline",
    "PipelineResult",
    "Response",
    "Verdict",
    "__version__",
    "extract_iocs",
    "score_alert",
]
