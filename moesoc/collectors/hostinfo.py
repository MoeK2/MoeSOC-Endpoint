"""Read-only facts about this computer's own names (Windows only).

Used to link this computer's NetBIOS and DNS domain names, and its short and fully
qualified host names. Nothing is changed; any failure simply yields no facts.
"""

from __future__ import annotations

import logging
import sys

from moesoc.core.domains import REASON_LOCAL_CONFIG, DomainAlias

log = logging.getLogger(__name__)

# COMPUTER_NAME_FORMAT values (sysinfoapi.h)
COMPUTER_NAME_NETBIOS = 0
COMPUTER_NAME_DNS_DOMAIN = 2
COMPUTER_NAME_DNS_FULLY_QUALIFIED = 3


def aliases_from_names(
    netbios_domain: str | None,
    dns_domain: str | None,
    netbios_host: str | None,
    dns_fqdn: str | None,
) -> list[DomainAlias]:
    """Pure logic, testable anywhere: pair each short name with its DNS form."""
    aliases: list[DomainAlias] = []
    if netbios_domain and dns_domain and netbios_domain.casefold() != dns_domain.casefold():
        aliases.append(
            DomainAlias(netbios_domain, dns_domain, REASON_LOCAL_CONFIG, "joined domain")
        )
    if netbios_host and dns_fqdn and netbios_host.casefold() != dns_fqdn.casefold():
        aliases.append(DomainAlias(netbios_host, dns_fqdn, REASON_LOCAL_CONFIG, "computer name"))
    return aliases


def local_domain_aliases() -> list[DomainAlias]:
    """This computer's own name pairs; empty off Windows or on any error."""
    if sys.platform != "win32":
        return []
    try:
        import win32api
        import win32net

        netbios_host = win32api.GetComputerNameEx(COMPUTER_NAME_NETBIOS)
        dns_fqdn = win32api.GetComputerNameEx(COMPUTER_NAME_DNS_FULLY_QUALIFIED)
        dns_domain = win32api.GetComputerNameEx(COMPUTER_NAME_DNS_DOMAIN)
        # Level 100 "langroup" is the NetBIOS domain (or workgroup) name.
        netbios_domain = win32net.NetWkstaGetInfo(None, 100).get("langroup")
    except Exception as exc:  # optional context: never fatal
        log.debug("Local domain names unavailable: %s", type(exc).__name__)
        return []
    if not dns_domain:  # workgroup computer: the workgroup name is not a domain
        netbios_domain = None
    return aliases_from_names(netbios_domain, dns_domain, netbios_host, dns_fqdn)


def local_standalone_hosts() -> list[str]:
    """This computer's short name when it is NOT joined to an Active Directory domain.

    Used only as identity context for failed logons recorded on this same computer (an
    unverified claimed domain cannot name another authority there). Empty off Windows, on
    any error, or when a DNS domain is configured. Microsoft Entra ID-joined computers have
    no DNS domain either; MoeSOC then still sees their S-1-12-1 account SIDs in the events
    and does not treat the computer as standalone (``DomainMap.from_events``).
    """
    if sys.platform != "win32":
        return []
    try:
        import win32api

        netbios_host = win32api.GetComputerNameEx(COMPUTER_NAME_NETBIOS)
        dns_domain = win32api.GetComputerNameEx(COMPUTER_NAME_DNS_DOMAIN)
    except Exception as exc:  # optional context: never fatal
        log.debug("Local join state unavailable: %s", type(exc).__name__)
        return []
    return [] if dns_domain or not netbios_host else [netbios_host]
