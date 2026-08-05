"""Core data models for the SOC automation pipeline.

An Alert is the pipeline's input (parsed from a Wazuh alert). IOCs are the
observables extracted from it. Enrichment, a triage Verdict, and a Response are
attached as the alert flows through the pipeline.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class IOCType(StrEnum):
    IP = "ip"
    DOMAIN = "domain"
    HASH = "hash"
    USER = "user"


@dataclass(frozen=True)
class IOC:
    """A single observable extracted from an alert."""

    type: IOCType
    value: str

    def __str__(self) -> str:
        return f"{self.type.value}:{self.value}"


class Action(StrEnum):
    """The triage engine's recommended disposition for an alert."""

    AUTO_CLOSE = "auto_close"
    ANALYST_REVIEW = "analyst_review"
    ESCALATE = "escalate"


@dataclass
class Alert:
    """A normalized security alert (from Wazuh) entering the pipeline."""

    id: str
    rule_id: str
    description: str
    level: int  # Wazuh rule level 0-15
    timestamp: str
    agent: str = "unknown"
    src_ip: str | None = None
    dst_ip: str | None = None
    user: str | None = None
    hashes: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_wazuh(cls, doc: dict[str, Any]) -> Alert:
        """Build an Alert from a Wazuh alert JSON document.

        Wazuh nests fields under 'rule', 'agent', and 'data'; this pulls the ones
        the pipeline cares about and keeps the full document in .raw.
        """
        rule = doc.get("rule", {})
        agent = doc.get("agent", {})
        data = doc.get("data", {})
        return cls(
            id=str(doc.get("id", doc.get("_id", "unknown"))),
            rule_id=str(rule.get("id", "0")),
            description=str(rule.get("description", "")),
            level=int(rule.get("level", 0)),
            timestamp=str(doc.get("timestamp", "")),
            agent=str(agent.get("name", "unknown")),
            src_ip=data.get("srcip") or data.get("src_ip"),
            dst_ip=data.get("dstip") or data.get("dst_ip"),
            user=_extract_user(data),
            hashes=_as_list(data.get("hash") or data.get("md5") or data.get("sha256")),
            domains=_as_list(data.get("domain") or data.get("url")),
            raw=doc,
        )


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v) for v in value]
    return [str(value)]


def _extract_user(data: dict[str, Any]) -> str | None:
    """Pull the subject user from the common Wazuh field locations."""
    direct = data.get("srcuser") or data.get("dstuser")
    if direct:
        return str(direct)
    win = data.get("win")
    if isinstance(win, dict):
        eventdata = win.get("eventdata", {})
        if isinstance(eventdata, dict):
            subject = eventdata.get("subjectUserName")
            if subject:
                return str(subject)
    return None


@dataclass
class Enrichment:
    """One enrichment source's verdict on one IOC."""

    source: str
    ioc: IOC
    malicious: bool
    score: int  # 0-100 normalized risk contribution
    summary: str
    details: dict[str, Any] = field(default_factory=dict)
    error: str | None = None


@dataclass
class Verdict:
    """The triage engine's output for an alert."""

    risk_score: int  # 0-100
    action: Action
    reasons: list[str] = field(default_factory=list)


@dataclass
class Response:
    """The action actually taken (or simulated) for an alert."""

    ticket_path: str | None = None
    containment: list[str] = field(default_factory=list)
    simulated: bool = True


@dataclass
class PipelineResult:
    """Everything the pipeline produced for one alert."""

    alert: Alert
    iocs: list[IOC]
    enrichments: list[Enrichment]
    verdict: Verdict
    response: Response
