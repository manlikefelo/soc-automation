"""Tests for config loading / offline-first behaviour."""

from __future__ import annotations

from soc_automation.config import Config


def test_defaults_to_offline(monkeypatch, tmp_path):
    monkeypatch.delenv("SOC_OFFLINE", raising=False)
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    cfg = Config.load(env_file=None)
    assert cfg.offline is True
    assert cfg.can_query(None) is False


def test_offline_false_with_key_allows_query(monkeypatch):
    monkeypatch.setenv("SOC_OFFLINE", "false")
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "k")
    cfg = Config.load(env_file=None)
    assert cfg.offline is False
    assert cfg.can_query(cfg.abuseipdb_key) is True


def test_offline_blocks_query_even_with_key(monkeypatch):
    monkeypatch.setenv("SOC_OFFLINE", "1")
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "k")
    cfg = Config.load(env_file=None)
    assert cfg.can_query(cfg.abuseipdb_key) is False


def test_no_key_blocks_query(monkeypatch):
    monkeypatch.setenv("SOC_OFFLINE", "false")
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    cfg = Config.load(env_file=None)
    assert cfg.can_query(cfg.abuseipdb_key) is False
