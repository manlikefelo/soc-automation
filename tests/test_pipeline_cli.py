"""Integration tests: the full pipeline and the CLI end to end."""

from __future__ import annotations

import json

import responses
from typer.testing import CliRunner

from soc_automation.cli import app
from soc_automation.enrichment.abuseipdb import API_URL as ABUSE_URL
from soc_automation.enrichment.abuseipdb import AbuseIPDBEnricher
from soc_automation.enrichment.base import Enricher
from soc_automation.models import Action, Alert
from soc_automation.pipeline import Pipeline

runner = CliRunner()

DCSYNC = {
    "id": "1.100",
    "timestamp": "t",
    "rule": {"id": "100012", "level": 12, "description": "DCSync"},
    "agent": {"name": "DC01"},
    "data": {"srcip": "10.10.10.40", "srcuser": "b.otieno"},
}
LOW = {
    "id": "2.200",
    "timestamp": "t",
    "rule": {"id": "5710", "level": 3, "description": "minor"},
    "agent": {"name": "UB01"},
    "data": {"srcip": "10.10.10.9"},
}


def test_pipeline_offline_dcsync_escalates(offline_config, null_cache, tmp_path):
    enrichers = [AbuseIPDBEnricher(offline_config, null_cache)]
    p = Pipeline(config=offline_config, enrichers=enrichers, tickets_dir=tmp_path)
    result = p.run(Alert.from_wazuh(DCSYNC))
    assert result.verdict.action is Action.ESCALATE
    assert result.response.ticket_path is not None
    assert any("block source IP" in c for c in result.response.containment)


def test_pipeline_low_alert_auto_closes(offline_config, null_cache):
    p = Pipeline(config=offline_config, enrichers=[AbuseIPDBEnricher(offline_config, null_cache)])
    result = p.run(Alert.from_wazuh(LOW))
    assert result.verdict.action is Action.AUTO_CLOSE


@responses.activate
def test_pipeline_live_enrichment_raises_score(live_config, null_cache):
    # a public-IP alert + a malicious AbuseIPDB verdict should escalate
    doc = {
        "id": "3.300", "timestamp": "t",
        "rule": {"id": "5710", "level": 10, "description": "ssh brute force"},
        "agent": {"name": "UB01"}, "data": {"srcip": "185.220.101.1"},
    }
    responses.add(
        responses.GET, ABUSE_URL, json={"data": {"abuseConfidenceScore": 100, "totalReports": 99}}
    )
    responses.add(responses.GET, "http://ip-api.com/json/185.220.101.1",
                  json={"status": "success", "country": "DE", "isp": "Tor"})
    responses.add(responses.GET, "https://rdap.org/ip/185.220.101.1",
                  json={"name": "TORNET", "entities": []})
    from soc_automation.enrichment import default_enrichers

    p = Pipeline(config=live_config, enrichers=default_enrichers(live_config, null_cache))
    result = p.run(Alert.from_wazuh(doc))
    assert result.verdict.action is Action.ESCALATE
    assert any(e.malicious for e in result.enrichments)


# --- CLI ------------------------------------------------------------------- #
def _write(tmp_path, name, doc):
    p = tmp_path / name
    p.write_text(json.dumps(doc), encoding="utf-8")
    return p


def test_cli_version():
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "soc-automation" in result.stdout


def test_cli_run_escalate_exit_1(tmp_path, monkeypatch):
    monkeypatch.setenv("SOC_OFFLINE", "1")
    alert_file = _write(tmp_path, "dcsync.json", DCSYNC)
    result = runner.invoke(app, ["run", str(alert_file)])
    assert result.exit_code == 1  # escalate -> non-zero (pager signal)
    assert "ESCALATE" in result.stdout


def test_cli_run_auto_close_exit_0(tmp_path, monkeypatch):
    monkeypatch.setenv("SOC_OFFLINE", "1")
    alert_file = _write(tmp_path, "low.json", LOW)
    result = runner.invoke(app, ["run", str(alert_file)])
    assert result.exit_code == 0
    assert "AUTO_CLOSE" in result.stdout


def test_cli_run_json(tmp_path, monkeypatch):
    monkeypatch.setenv("SOC_OFFLINE", "1")
    alert_file = _write(tmp_path, "dcsync.json", DCSYNC)
    result = runner.invoke(app, ["run", str(alert_file), "--json"])
    # exit 1 due to escalate, but stdout is still valid JSON
    payload = json.loads(result.stdout)
    assert payload[0]["action"] == "escalate"
    assert payload[0]["rule_id"] == "100012"


def test_cli_run_directory(tmp_path, monkeypatch):
    monkeypatch.setenv("SOC_OFFLINE", "1")
    _write(tmp_path, "a.json", DCSYNC)
    _write(tmp_path, "b.json", LOW)
    result = runner.invoke(app, ["run", str(tmp_path)])
    assert "ESCALATE" in result.stdout
    assert "AUTO_CLOSE" in result.stdout


def test_cli_missing_file_exit_2():
    result = runner.invoke(app, ["run", "does-not-exist.json"])
    assert result.exit_code == 2


def test_cli_bad_json_exit_2(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    result = runner.invoke(app, ["run", str(bad)])
    assert result.exit_code == 2


def test_applies_to_base():
    # a base Enricher with no `handles` applies to nothing
    class Dummy(Enricher):
        def _query_live(self, ioc):  # pragma: no cover - never called
            raise NotImplementedError

    from soc_automation.models import IOC, IOCType

    d = Dummy.__new__(Dummy)
    d.handles = ()
    assert d.applies_to(IOC(IOCType.IP, "1.1.1.1")) is False
