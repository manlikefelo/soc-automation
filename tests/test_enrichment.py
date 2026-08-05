"""Enrichment tests with mocked API responses - the QA-background centerpiece.

Every live HTTP call is mocked with `responses`, so the suite needs no keys and
no network. We assert both directions: a malicious verdict when the API says so,
a clean one when it doesn't, and graceful handling of rate limits and errors.
"""

from __future__ import annotations

import responses

from soc_automation.enrichment.abuseipdb import API_URL as ABUSE_URL
from soc_automation.enrichment.abuseipdb import AbuseIPDBEnricher
from soc_automation.enrichment.geoip import GeoIPEnricher
from soc_automation.enrichment.virustotal import VirusTotalEnricher
from soc_automation.enrichment.whois import WhoisEnricher
from soc_automation.models import IOC, IOCType

PUBLIC_IP = IOC(IOCType.IP, "185.220.101.1")
PRIVATE_IP = IOC(IOCType.IP, "10.10.10.40")
HASH = IOC(IOCType.HASH, "44d88612fea8a8f36de82e1278abb02f")


# --- AbuseIPDB ------------------------------------------------------------- #
@responses.activate
def test_abuseipdb_flags_malicious_ip(live_config, null_cache):
    responses.add(
        responses.GET,
        ABUSE_URL,
        json={"data": {"abuseConfidenceScore": 92, "totalReports": 40, "countryCode": "RU"}},
        status=200,
    )
    e = AbuseIPDBEnricher(live_config, null_cache).enrich(PUBLIC_IP)
    assert e.malicious is True
    assert e.score == 92
    assert "92%" in e.summary


@responses.activate
def test_abuseipdb_clean_ip_not_malicious(live_config, null_cache):
    responses.add(
        responses.GET, ABUSE_URL, json={"data": {"abuseConfidenceScore": 3, "totalReports": 0}}
    )
    e = AbuseIPDBEnricher(live_config, null_cache).enrich(PUBLIC_IP)
    assert e.malicious is False
    assert e.score == 3


@responses.activate
def test_abuseipdb_rate_limited(live_config, null_cache):
    responses.add(responses.GET, ABUSE_URL, status=429)
    e = AbuseIPDBEnricher(live_config, null_cache).enrich(PUBLIC_IP)
    assert e.error is not None
    assert "rate limited" in e.summary


@responses.activate
def test_abuseipdb_server_error(live_config, null_cache):
    responses.add(responses.GET, ABUSE_URL, status=500)
    e = AbuseIPDBEnricher(live_config, null_cache).enrich(PUBLIC_IP)
    assert e.error is not None
    assert "HTTP error 500" in e.summary


def test_abuseipdb_skips_private_ip(live_config, null_cache):
    # no responses registered -> if it tried to call, it'd fail loudly
    e = AbuseIPDBEnricher(live_config, null_cache).enrich(PRIVATE_IP)
    assert e.error is None
    assert "private/lab IP" in e.summary


def test_abuseipdb_offline_not_queried(offline_config, null_cache):
    e = AbuseIPDBEnricher(offline_config, null_cache).enrich(PUBLIC_IP)
    assert "not queried" in e.summary
    assert e.error is None


def test_abuseipdb_no_key_not_queried(tmp_path, null_cache):
    from soc_automation.config import Config

    cfg = Config(abuseipdb_key=None, virustotal_key=None, offline=False, cache_dir=tmp_path)
    e = AbuseIPDBEnricher(cfg, null_cache).enrich(PUBLIC_IP)
    assert "no API key" in e.summary


# --- VirusTotal ------------------------------------------------------------ #
@responses.activate
def test_virustotal_flags_malicious_hash(live_config, null_cache):
    responses.add(
        responses.GET,
        f"https://www.virustotal.com/api/v3/files/{HASH.value}",
        json={"data": {"attributes": {"last_analysis_stats": {"malicious": 58, "harmless": 2}}}},
    )
    e = VirusTotalEnricher(live_config, null_cache).enrich(HASH)
    assert e.malicious is True
    assert e.score > 50
    assert "58/" in e.summary


@responses.activate
def test_virustotal_clean_hash(live_config, null_cache):
    responses.add(
        responses.GET,
        f"https://www.virustotal.com/api/v3/files/{HASH.value}",
        json={"data": {"attributes": {"last_analysis_stats": {"malicious": 0, "harmless": 70}}}},
    )
    e = VirusTotalEnricher(live_config, null_cache).enrich(HASH)
    assert e.malicious is False


def test_virustotal_ignores_non_hash(live_config, null_cache):
    e = VirusTotalEnricher(live_config, null_cache).enrich(PUBLIC_IP)
    assert "not applicable" in e.summary


# --- GeoIP (keyless) ------------------------------------------------------- #
@responses.activate
def test_geoip_returns_location(live_config, null_cache):
    responses.add(
        responses.GET,
        f"http://ip-api.com/json/{PUBLIC_IP.value}",
        json={"status": "success", "country": "Germany", "city": "Berlin", "isp": "Tor"},
    )
    e = GeoIPEnricher(live_config, null_cache).enrich(PUBLIC_IP)
    assert e.malicious is False  # context only
    assert "Germany" in e.summary
    assert e.details["country"] == "Germany"


def test_geoip_offline_skips(offline_config, null_cache):
    e = GeoIPEnricher(offline_config, null_cache).enrich(PUBLIC_IP)
    assert "offline" in e.summary


def test_geoip_skips_private(live_config, null_cache):
    e = GeoIPEnricher(live_config, null_cache).enrich(PRIVATE_IP)
    assert "private/lab IP" in e.summary


# --- WHOIS/RDAP (keyless) -------------------------------------------------- #
@responses.activate
def test_whois_ip_owner(live_config, null_cache):
    responses.add(
        responses.GET,
        f"https://rdap.org/ip/{PUBLIC_IP.value}",
        json={"name": "TORNET", "handle": "NET-185-220", "entities": []},
    )
    e = WhoisEnricher(live_config, null_cache).enrich(PUBLIC_IP)
    assert e.malicious is False
    assert "TORNET" in e.summary


@responses.activate
def test_whois_domain(live_config, null_cache):
    responses.add(
        responses.GET,
        "https://rdap.org/domain/evil.example",
        json={"ldhName": "evil.example", "entities": []},
    )
    e = WhoisEnricher(live_config, null_cache).enrich(IOC(IOCType.DOMAIN, "evil.example"))
    assert e.details["name"] == "evil.example"


@responses.activate
def test_whois_extracts_vcard_registrant_name(live_config, null_cache):
    # RDAP entity with a vCard 'fn' (full name) -> used as the registrant
    responses.add(
        responses.GET,
        f"https://rdap.org/ip/{PUBLIC_IP.value}",
        json={
            "name": "NET-BLOCK",
            "entities": [
                {"vcardArray": ["vcard", [["version", {}, "text", "4.0"],
                                          ["fn", {}, "text", "Evil Hosting Ltd"]]]}
            ],
        },
    )
    e = WhoisEnricher(live_config, null_cache).enrich(PUBLIC_IP)
    assert "Evil Hosting Ltd" in e.summary
    assert e.details["registrar"] == "Evil Hosting Ltd"


@responses.activate
def test_whois_falls_back_to_entity_handle(live_config, null_cache):
    responses.add(
        responses.GET,
        f"https://rdap.org/ip/{PUBLIC_IP.value}",
        json={"name": "NET", "entities": [{"handle": "ORG-XYZ"}]},
    )
    e = WhoisEnricher(live_config, null_cache).enrich(PUBLIC_IP)
    assert e.details["registrar"] == "ORG-XYZ"


def test_whois_offline_skips(offline_config, null_cache):
    e = WhoisEnricher(offline_config, null_cache).enrich(PUBLIC_IP)
    assert "offline" in e.summary


@responses.activate
def test_geoip_unresolvable_returns_skip(live_config, null_cache):
    responses.add(
        responses.GET, f"http://ip-api.com/json/{PUBLIC_IP.value}", json={"status": "fail"}
    )
    e = GeoIPEnricher(live_config, null_cache).enrich(PUBLIC_IP)
    assert "no geolocation" in e.summary


# --- caching --------------------------------------------------------------- #
@responses.activate
def test_result_is_cached(live_config, tmp_path):
    from soc_automation.cache import Cache

    cache = Cache(tmp_path)
    responses.add(
        responses.GET, ABUSE_URL, json={"data": {"abuseConfidenceScore": 80, "totalReports": 5}}
    )
    enr = AbuseIPDBEnricher(live_config, cache)
    first = enr.enrich(PUBLIC_IP)
    assert first.score == 80
    # second call: registered response is consumed; a cache miss would raise.
    second = enr.enrich(PUBLIC_IP)
    assert second.score == 80
    assert "cached" in second.summary
    assert len(responses.calls) == 1  # only one real HTTP call was made
