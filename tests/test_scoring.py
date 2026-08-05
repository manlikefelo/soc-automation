"""Tests for the triage scoring engine."""

from __future__ import annotations

from soc_automation.models import IOC, Action, Alert, Enrichment, IOCType
from soc_automation.scoring import score_alert


def alert(level: int, rule_id: str = "1000") -> Alert:
    return Alert(id="a", rule_id=rule_id, description="d", level=level, timestamp="t")


def mal(source: str, score: int) -> Enrichment:
    ioc = IOC(IOCType.IP, "1.2.3.4")
    return Enrichment(source, ioc, malicious=True, score=score, summary="bad")


def test_critical_level_escalates_on_severity():
    v = score_alert(alert(12), [])
    assert v.action is Action.ESCALATE
    assert any("critical" in r for r in v.reasons)


def test_high_reputation_pushes_to_escalate():
    # level 8 base ~37, +30 from a 100-score malicious IP -> 67... plus review;
    # bump with a level that crosses 70
    v = score_alert(alert(10), [mal("abuseipdb", 100)])
    assert v.risk_score >= 70
    assert v.action is Action.ESCALATE


def test_malicious_forces_at_least_review():
    v = score_alert(alert(3), [mal("virustotal", 60)])
    assert v.action in (Action.ANALYST_REVIEW, Action.ESCALATE)
    assert v.action is not Action.AUTO_CLOSE


def test_low_level_no_signal_auto_closes():
    v = score_alert(alert(3), [])
    assert v.action is Action.AUTO_CLOSE
    assert v.risk_score < 40


def test_score_is_capped_at_100():
    v = score_alert(alert(15), [mal("abuseipdb", 100)])
    assert v.risk_score == 100


def test_context_enrichment_does_not_raise_score():
    ctx = Enrichment(
        "geoip", IOC(IOCType.IP, "1.2.3.4"), malicious=False, score=0,
        summary="DE", details={"country": "DE"},
    )
    with_ctx = score_alert(alert(5), [ctx]).risk_score
    without = score_alert(alert(5), []).risk_score
    assert with_ctx == without


def test_errors_noted_in_reasons():
    err = Enrichment(
        "abuseipdb", IOC(IOCType.IP, "1.2.3.4"), False, 0, "rate limited", error="rate limited"
    )
    v = score_alert(alert(5), [err])
    assert any("errored" in r for r in v.reasons)
