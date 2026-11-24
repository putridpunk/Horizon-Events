"""Windows Firewall blocking by remote IP, through netsh. Only ever called with an address that has been parsed
by `ipaddress`, so nothing user-supplied reaches the command line unchecked."""
from __future__ import annotations

import ipaddress
import socket

from app.system.winutil import run_command, system_tool

RULE_PREFIX = "Horizon Events block "
# Rules whose alerts may propose a block. HZ-007 (the ML rule) is deliberately absent: a statistical hint alone
# is not grounds to cut an address off.
BLOCK_RULES = ("HZ-001", "HZ-003", "HZ-006")


def netsh() -> str:
    return system_tool("netsh.exe")


def rule_name(ip: str) -> str:
    return f"{RULE_PREFIX}{ipaddress.ip_address(ip)}"


def add_rule_args(ip: str) -> list[str]:
    ip = str(ipaddress.ip_address(ip))
    return ["advfirewall", "firewall", "add", "rule", f"name={rule_name(ip)}", "dir=in", "action=block",
            f"remoteip={ip}", "enable=yes", "description=Added by Horizon Events"]


def delete_rule_args(ip: str) -> list[str]:
    return ["advfirewall", "firewall", "delete", "rule", f"name={rule_name(ip)}"]


def rule_exists(ip: str, runner=run_command) -> bool:
    """Reading a rule needs no administrator rights, so this checks the result of a block (or its removal)."""
    try:
        code, out = runner([netsh(), "advfirewall", "firewall", "show", "rule", f"name={rule_name(ip)}"], timeout=15.0)
    except (OSError, TimeoutError):
        return False
    return code == 0 and RULE_PREFIX.strip() in out


def own_addresses() -> set[str]:
    found = {"127.0.0.1", "::1"}
    try:
        found.update(socket.gethostbyname_ex(socket.gethostname())[2])
    except OSError:
        pass
    return found


def parse_networks(values) -> list:
    """Allowlist entries (addresses or CIDR ranges) -> networks. Raises ValueError naming the bad entry."""
    nets = []
    for raw in values or []:
        text = str(raw).strip()
        if not text:
            continue
        try:
            nets.append(ipaddress.ip_network(text, strict=False))
        except ValueError as exc:
            raise ValueError(f"Not an IP address or range: {text}") from exc
    return nets


def blockable_reason(ip: str | None, allowlist=(), allow_private: bool = False, own: set[str] | None = None) -> str | None:
    """None when the address may be blocked, otherwise the reason it must not be (shown to the user)."""
    if not ip:
        return "The alert has no source address."
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "The source is not a valid IP address."
    if addr.is_loopback or addr.is_unspecified or addr.is_multicast or addr.is_link_local or addr.is_reserved:
        return "This is not a routable address."
    if own is not None and str(addr) in own:
        return "This is one of this computer's own addresses."
    if any(addr in net for net in parse_networks(allowlist) if net.version == addr.version):
        return "This address is on your allowlist."
    if not addr.is_global and not allow_private:
        return "This is a private-network address. Block it at your router, or allow blocking private addresses in settings."
    return None
