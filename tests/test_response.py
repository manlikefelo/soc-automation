"""Tests for response actions - tickets and simulated containment."""

from __future__ import annotations

from soc_automation.models import IOC, Action, Alert, IOCType, Verdict
from soc_automation.response import build_containment, render_ticket, respond


def escalate_alert() -> Alert:
    return Alert(
        id="a1", rule_id="100012", description="DCSync", level=12, timestamp="t",
        agent="DC01", src_ip="10.10.10.40", user="b.otieno",
    )


def test_containment_only_on_escalate():
    a = escalate_alert()
    esc = Verdict(risk_score=80, action=Action.ESCALATE)
    rev = Verdict(risk_score=50, action=Action.ANALYST_REVIEW)
    assert build_containment(a, esc)  # non-empty
    assert build_containment(a, rev) == []


def test_containment_includes_dcsync_krbtgt():
    steps = build_containment(escalate_alert(), Verdict(90, Action.ESCALATE))
    assert any("krbtgt" in s for s in steps)
    assert any("block source IP" in s for s in steps)
    assert all("SIMULATED" in s for s in steps)


def test_auto_close_writes_no_ticket(tmp_path):
    a = Alert(id="a", rule_id="1", description="d", level=2, timestamp="t")
    r = respond(a, [], [], Verdict(10, Action.AUTO_CLOSE), tickets_dir=tmp_path)
    assert r.ticket_path is None
    assert list(tmp_path.iterdir()) == []


def test_escalate_writes_ticket(tmp_path):
    a = escalate_alert()
    v = Verdict(80, Action.ESCALATE, reasons=["level 12"])
    iocs = [IOC(IOCType.IP, "10.10.10.40")]
    r = respond(a, iocs, [], v, tickets_dir=tmp_path)
    assert r.ticket_path is not None
    content = (tmp_path / f"{a.id}-{a.rule_id}.md").read_text(encoding="utf-8")
    assert "ESCALATE" in content
    assert "10.10.10.40" in content


def test_render_ticket_contains_sections():
    a = escalate_alert()
    v = Verdict(80, Action.ESCALATE, reasons=["reason one"])
    md = render_ticket(a, [IOC(IOCType.IP, "10.10.10.40")], [], v, ["[SIMULATED] block IP"])
    assert "## Observables" in md
    assert "## Triage reasoning" in md
    assert "## Recommended containment" in md
