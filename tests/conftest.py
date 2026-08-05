"""Shared fixtures. Tests are hermetic: no real network, no real keys, no disk cache."""

from __future__ import annotations

import pytest

from soc_automation.cache import NullCache
from soc_automation.config import Config


@pytest.fixture
def offline_config(tmp_path):
    """Offline config with no keys - the default safe posture."""
    return Config(abuseipdb_key=None, virustotal_key=None, offline=True, cache_dir=tmp_path)


@pytest.fixture
def live_config(tmp_path):
    """Online config WITH keys, so live-query paths are exercised (HTTP is mocked)."""
    return Config(abuseipdb_key="k-abuse", virustotal_key="k-vt", offline=False, cache_dir=tmp_path)


@pytest.fixture
def null_cache():
    return NullCache()
