"""Extract observables (IOCs) from an alert.

Pulls the structured fields off an Alert (src/dst IP, user, hashes, domains) and
de-duplicates them into a stable, ordered list of IOCs the enrichment layer can
work through. IPs in private/reserved ranges are kept but flagged by the
enrichers (a private lab IP has no public reputation).
"""

from __future__ import annotations

import ipaddress

from soc_automation.models import IOC, Alert, IOCType


def is_public_ip(value: str) -> bool:
    """True if value is a valid, globally-routable IP address."""
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return not (ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_link_local)


def extract_iocs(alert: Alert) -> list[IOC]:
    """Return a de-duplicated, ordered list of IOCs from an alert."""
    seen: set[tuple[str, str]] = set()
    iocs: list[IOC] = []

    def add(ioc_type: IOCType, value: str | None) -> None:
        if not value:
            return
        key = (ioc_type.value, value)
        if key in seen:
            return
        seen.add(key)
        iocs.append(IOC(ioc_type, value))

    add(IOCType.IP, alert.src_ip)
    add(IOCType.IP, alert.dst_ip)
    add(IOCType.USER, alert.user)
    for h in alert.hashes:
        add(IOCType.HASH, h)
    for d in alert.domains:
        add(IOCType.DOMAIN, d)

    return iocs
