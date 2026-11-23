"""Public blocklist feeds: definitions, parsers and a local IP matcher. Pure Python, no network."""
from __future__ import annotations

import ipaddress
import json
from typing import Callable

FEEDS: dict[str, dict] = {
    "feodo": {
        "name": "abuse.ch Feodo Tracker",
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
        "description": "IP addresses of botnet command-and-control servers (CC0).",
    },
    "spamhaus_drop": {
        "name": "Spamhaus DROP",
        "url": "https://www.spamhaus.org/drop/drop_v4.json",
        "description": "Netblocks hijacked or controlled by criminal operations (free use; at most hourly fetches).",
    },
}

_DOC_NETWORKS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")]


def parse_feodo(text: str) -> list[str]:
    """One IP per line; '#' starts a comment. Returns CIDR strings (single hosts as /32 or /128)."""
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            out.append(str(ipaddress.ip_network(line.split()[0])))
        except ValueError:
            continue
    return out


def parse_spamhaus_drop(text: str) -> list[str]:
    """JSON Lines with a 'cidr' field. Malformed lines and lines without a valid cidr are skipped."""
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            cidr = json.loads(line).get("cidr")
            out.append(str(ipaddress.ip_network(cidr)))
        except (ValueError, TypeError, AttributeError):
            continue
    return out


PARSERS: dict[str, Callable[[str], list[str]]] = {"feodo": parse_feodo, "spamhaus_drop": parse_spamhaus_drop}


def checkable(ip: str | None) -> bool:
    """True for addresses that could be public. Private, loopback, link-local and similar are skipped;
    the reserved documentation ranges are allowed so the synthetic demo data can be matched."""
    try:
        addr = ipaddress.ip_address((ip or "").strip())
    except ValueError:
        return False
    if any(addr in net for net in _DOC_NETWORKS):
        return True
    return not (addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast
                or addr.is_unspecified or addr.is_reserved)


class IpMatcher:
    """Checks IPs against feed entries in memory; nothing is sent anywhere."""

    def __init__(self, entries: dict[str, list[str]]):
        self._nets: dict[str, list] = {}
        for feed_id, cidrs in entries.items():
            nets = []
            for c in cidrs:
                try:
                    nets.append(ipaddress.ip_network(c))
                except ValueError:
                    continue
            self._nets[feed_id] = nets

    def lookup(self, ip: str | None) -> list[str]:
        if not checkable(ip):
            return []
        addr = ipaddress.ip_address(ip.strip())
        return sorted(feed for feed, nets in self._nets.items() if any(addr in n for n in nets))
