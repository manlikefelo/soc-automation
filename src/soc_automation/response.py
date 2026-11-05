"""Response actions for triaged alerts.

Two kinds of action, matched to the verdict:

  - a TICKET is written for anything a human needs to see (analyst-review /
    escalate). It's a self-contained markdown incident record.
  - CONTAINMENT is *simulated*: the pipeline records exactly what it would do
    (block the source IP, isolate the host) without needing production access.
    This keeps the repo safe to run anywhere while documenting the real intent.

Nothing here talks to production. The containment strings describe the action a
live integration (Wazuh active-response, a firewall API, EDR isolation) would
perform.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from soc_automation.models import IOC, Action, Alert, Enrichment, Response, Verdict


def build_containment(alert: Alert, verdict: Verdict) -> list[str]:
    """Describe the containment steps that WOULD be taken for this verdict."""
    if verdict.action is not Action.ESCALATE:
        return []
    steps: list[str] = []
    if alert.src_ip:
        steps.append(f"[SIMULATED] block source IP {alert.src_ip} at the perimeter firewall")
    if alert.agent and alert.agent != "unknown":
        steps.append(f"[SIMULATED] isolate host {alert.agent} via EDR/Wazuh active-response")
    if alert.user:
        steps.append(f"[SIMULATED] disable account {alert.user} pending investigation")
    if alert.rule_id == "100012":  # DCSync
        steps.append("[SIMULATED] rotate krbtgt password twice (assume domain compromise)")
    return steps


def render_ticket(
    alert: Alert,
    iocs: list[IOC],
    enrichments: list[Enrichment],
    verdict: Verdict,
    containment: list[str],
) -> str:
    """Render a self-contained markdown incident ticket."""
    lines = [
        f"# [{verdict.action.value.upper()}] {alert.description}",
        "",
        f"- **Alert ID:** {alert.id}",
        f"- **Wazuh rule:** {alert.rule_id} (level {alert.level})",
        f"- **Time:** {alert.timestamp}",
        f"- **Host:** {alert.agent}",
        f"- **Risk score:** {verdict.risk_score}/100",
        f"- **Generated:** {datetime.now(UTC).isoformat()}",
        "",
        "## Observables",
    ]
    lines += [f"- `{ioc}`" for ioc in iocs] or ["- (none extracted)"]

    lines += ["", "## Enrichment"]
    for e in enrichments:
        flag = "malicious" if e.malicious else ("error" if e.error else "context")
        lines.append(f"- **{e.source}** `{e.ioc}`: {e.summary} ({flag})")

    lines += ["", "## Triage reasoning"]
    lines += [f"- {r}" for r in verdict.reasons]

    lines += ["", "## Recommended containment"]
    lines += [f"- {c}" for c in containment] or ["- none (below escalation threshold)"]

    return "\n".join(lines) + "\n"


def respond(
    alert: Alert,
    iocs: list[IOC],
    enrichments: list[Enrichment],
    verdict: Verdict,
    *,
    tickets_dir: Path | None = None,
) -> Response:
    """Take (or simulate) the response for an alert, returning a Response."""
    containment = build_containment(alert, verdict)

    if verdict.action is Action.AUTO_CLOSE:
        return Response(ticket_path=None, containment=containment, simulated=True)

    ticket_path: str | None = None
    if tickets_dir is not None:
        tickets_dir.mkdir(parents=True, exist_ok=True)
        path = tickets_dir / f"{alert.id}-{alert.rule_id}.md"
        path.write_text(
            render_ticket(alert, iocs, enrichments, verdict, containment), encoding="utf-8"
        )
        ticket_path = str(path)

    return Response(ticket_path=ticket_path, containment=containment, simulated=True)
