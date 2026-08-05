"""Tests for the Alert model, IOC extraction, and public-IP detection."""

from __future__ import annotations

from soc_automation.extract import extract_iocs, is_public_ip
from soc_automation.models import Alert, IOCType


def test_from_wazuh_parses_core_fields():
    doc = {
        "id": "123.456",
        "timestamp": "2026-07-31T14:00:00+0300",
        "rule": {"id": "100012", "level": 12, "description": "DCSync"},
        "agent": {"name": "DC01"},
        "data": {"srcip": "10.10.10.40", "srcuser": "b.otieno"},
    }
    a = Alert.from_wazuh(doc)
    assert a.rule_id == "100012"
    assert a.level == 12
    assert a.agent == "DC01"
    assert a.src_ip == "10.10.10.40"
    assert a.user == "b.otieno"


def test_from_wazuh_extracts_windows_subject_user():
    doc = {
        "rule": {"id": "1", "level": 5, "description": "d"},
        "data": {"win": {"eventdata": {"subjectUserName": "attacker"}}},
    }
    assert Alert.from_wazuh(doc).user == "attacker"


def test_from_wazuh_handles_missing_fields():
    a = Alert.from_wazuh({"rule": {}})
    assert a.level == 0
    assert a.src_ip is None
    assert a.user is None


def test_from_wazuh_hash_and_domain():
    doc = {
        "rule": {"id": "1", "level": 5, "description": "d"},
        "data": {"hash": "abc123", "url": "evil.example"},
    }
    a = Alert.from_wazuh(doc)
    assert a.hashes == ["abc123"]
    assert a.domains == ["evil.example"]


def test_extract_iocs_dedupes():
    a = Alert(
        id="1", rule_id="1", description="d", level=5, timestamp="t",
        src_ip="1.2.3.4", dst_ip="1.2.3.4", user="bob", hashes=["h1", "h1"],
    )
    iocs = extract_iocs(a)
    values = [str(i) for i in iocs]
    assert values.count("ip:1.2.3.4") == 1
    assert values.count("hash:h1") == 1
    assert "user:bob" in values


def test_extract_iocs_preserves_types():
    a = Alert(id="1", rule_id="1", description="d", level=5, timestamp="t", src_ip="8.8.8.8")
    iocs = extract_iocs(a)
    assert iocs[0].type is IOCType.IP


def test_is_public_ip():
    assert is_public_ip("8.8.8.8") is True
    assert is_public_ip("185.220.101.1") is True
    assert is_public_ip("10.10.10.40") is False
    assert is_public_ip("127.0.0.1") is False
    assert is_public_ip("192.168.1.1") is False
    assert is_public_ip("not-an-ip") is False
