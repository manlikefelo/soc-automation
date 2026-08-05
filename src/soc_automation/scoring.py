"""Triage scoring engine.

Combines the alert's own severity with the enrichment signals into a single
0-100 risk score and a recommended action. The logic is deliberately simple and
transparent - a SOC analyst should be able to read it and predict the outcome,
which is exactly what makes an automated triage defensible.

Scoring model
-------------
1. Base score from the Wazuh rule level (0-15 -> 0-70). Severe rules like DCSync
   (level 12) start high on their own.
2. Reputation boost: the single highest malicious enrichment score contributes up
   to +30 (an IP with 100% abuse confidence, or a hash many engines flag).
3. Context (GeoIP/WHOIS) never adds risk by itself; it's recorded as a reason.

Action thresholds
-----------------
  score >= 70, OR alert level >= 12   -> ESCALATE       (likely true positive)
  40 <= score < 70, OR any malicious  -> ANALYST_REVIEW (needs a human)
  otherwise                           -> AUTO_CLOSE     (low risk, close with a note)

A critical-severity rule (Wazuh level >= 12, e.g. DCSync) escalates on severity
alone - reputation can't argue a domain-compromise signal down, and in offline /
private-lab mode there is no public reputation to add.
"""

from __future__ import annotations

from soc_automation.models import Action, Alert, Enrichment, Verdict

ESCALATE_AT = 70
REVIEW_AT = 40


def _base_from_level(level: int) -> int:
    """Map a Wazuh rule level (0-15) onto a 0-70 base score."""
    clamped = max(0, min(15, level))
    return round(clamped / 15 * 70)


def score_alert(alert: Alert, enrichments: list[Enrichment]) -> Verdict:
    reasons: list[str] = []

    base = _base_from_level(alert.level)
    reasons.append(f"alert level {alert.level} -> base score {base}")

    malicious = [e for e in enrichments if e.malicious]
    rep_boost = 0
    if malicious:
        top = max(malicious, key=lambda e: e.score)
        rep_boost = round(top.score / 100 * 30)
        reasons.append(
            f"{top.source} flagged {top.ioc} as malicious ({top.summary}) -> +{rep_boost}"
        )

    # Note genuine context signals (an actual geo/owner lookup that returned data)
    # as reasons, without changing the score. Skipped/offline lookups are ignored.
    for e in enrichments:
        if e.source in ("geoip", "whois") and e.details and not e.error:
            reasons.append(f"context: {e.source} {e.ioc} = {e.summary}")

    errors = [e for e in enrichments if e.error]
    if errors:
        reasons.append(f"{len(errors)} enrichment source(s) errored - treat score as a floor")

    score = min(100, base + rep_boost)

    # A critical-severity alert (Wazuh level >= 12, e.g. DCSync) is escalation-worthy
    # on its own - reputation enrichment can't lower a domain-compromise signal, and
    # in offline/private-lab mode there's no reputation to add. Severity floors it.
    critical_severity = alert.level >= 12
    if critical_severity:
        reasons.append(f"alert level {alert.level} >= 12 (critical) -> escalate on severity")

    if score >= ESCALATE_AT or critical_severity:
        action = Action.ESCALATE
    elif score >= REVIEW_AT or malicious:
        # any malicious signal forces at least a human look, even on a low base
        action = Action.ANALYST_REVIEW
    else:
        action = Action.AUTO_CLOSE

    return Verdict(risk_score=score, action=action, reasons=reasons)
