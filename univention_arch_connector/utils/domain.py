#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2017-2025 Univention GmbH
# SPDX-License-Identifier: AGPL-3.0-only
#
# Ported from univention-domain-join (upstream module:
# univention_domain_join/utils/domain.py). The `resolvectl`-output parsing
# already assumes systemd-resolved, which matches Arch exactly, so the only
# change is replacing the `IPy` dependency (not packaged for Arch) with the
# stdlib `ipaddress` module, and `Resolver.query` (removed in modern
# dnspython) with its replacement `Resolver.resolve`.
#
# Two Arch-port additions: a host's DNS domain is often a subdomain of the
# UCS domain (e.g. host.site.example.com in UCS domain example.com), so
# candidate domains are walked up towards the root until one has the UCS
# `_domaincontroller_master._tcp` SRV record (find_ucs_domain()). And since
# not every Arch system runs systemd-resolved, get_nameservers() falls back
# to /etc/resolv.conf. See ../../NOTICE.md.

import ipaddress
import re
import socket
import subprocess
from pathlib import Path
from typing import Iterable, List, Set

import dns.resolver
import netifaces


RESOLV_CONF = Path('/etc/resolv.conf')


def has_ucs_master_srv_record(domain: str) -> bool:
    try:
        dns.resolver.Resolver().resolve('_domaincontroller_master._tcp.%s.' % (domain,), 'SRV')
    except Exception:
        return False
    return True


def find_ucs_domain(domain: str) -> str:
    """Return ``domain`` or its closest parent domain that is a UCS
    domain, or "" if none is. The bare top-level domain is never tried.
    """
    labels = domain.strip('.').split('.')
    for i in range(len(labels) - 1):
        candidate = '.'.join(labels[i:])
        if has_ucs_master_srv_record(candidate):
            return candidate
    return ""


def get_master_ip_through_dns(domain: str) -> str:
    resolver = dns.resolver.Resolver()
    try:
        response = resolver.resolve('_domaincontroller_master._tcp.%s.' % (domain,), 'SRV')
        master_fqdn = response[0].target.canonicalize().split(1)[0].to_text()
    except Exception:
        return ""
    return socket.gethostbyname(master_fqdn)


def get_ucs_domainname() -> str:
    domainname = get_ucs_domainname_via_local_configuration()
    if not domainname:
        domainname = get_ucs_domainname_via_reverse_dns()
    if not domainname:
        domainname = get_ucs_domainname_of_dns_server()
    return domainname


def get_ucs_domainname_via_local_configuration() -> str:
    try:
        domainname = socket.getfqdn().split('.', 1)[1]
    except Exception:
        return ""
    return find_ucs_domain(domainname)


def get_ucs_domainname_via_reverse_dns() -> str:
    return ips2name(get_all_ip_addresses())


def get_ucs_domainname_of_dns_server() -> str:
    return ips2name(get_nameservers())


def get_nameservers() -> Set[str]:
    try:
        output = subprocess.check_output(['resolvectl'], stderr=subprocess.DEVNULL)
    except (OSError, subprocess.CalledProcessError):
        return get_nameservers_from_resolv_conf()

    return parse_resolvectl_nameservers(output.decode())


def parse_resolvectl_nameservers(output: str) -> Set[str]:
    """Collect the "DNS Servers:" of `resolvectl` output, including
    continuation lines. "Fallback DNS Servers:" (resolved's built-in public
    resolvers) are skipped, they can't know about the UCS domain.
    """
    nameservers: Set[str] = set()
    in_dns_servers = False
    for line in output.splitlines():
        # "Label: value" - the colon of a label is followed by whitespace,
        # which never happens inside an IPv6 address.
        match = re.match(r'^\s*([^:\s][^:]*):(?:\s+|$)(.*)$', line)
        if match:
            in_dns_servers = match.group(1).strip() == 'DNS Servers'
            values = match.group(2)
        else:
            values = line
        if in_dns_servers:
            for token in values.split():
                address = _strip_resolved_suffixes(token)
                if is_only_ip(address):
                    nameservers.add(address)
    return nameservers


def _strip_resolved_suffixes(token: str) -> str:
    return token.strip().split('#', 1)[0].split('%', 1)[0]


def get_nameservers_from_resolv_conf() -> Set[str]:
    nameservers: Set[str] = set()
    try:
        lines = RESOLV_CONF.read_text().splitlines()
    except OSError:
        return nameservers
    for line in lines:
        fields = line.split()
        if len(fields) >= 2 and fields[0] == 'nameserver' and is_only_ip(fields[1]):
            nameservers.add(fields[1])
    return nameservers


def is_only_ip(line: str) -> bool:
    try:
        ipaddress.ip_address(line.strip())
        return True
    except ValueError:
        return False


def get_all_ip_addresses() -> List[str]:
    ip_addresses = []
    for interface in netifaces.interfaces():
        # Skip the loopback device.
        if interface == 'lo':
            continue
        ip_addresses += get_ipv4_addresses(interface)
        ip_addresses += get_ipv6_addresses(interface)
    return ip_addresses


def get_ipv4_addresses(interface: str) -> List[str]:
    short_addresses = []
    if netifaces.AF_INET in netifaces.ifaddresses(interface):
        ipv4_addresses = netifaces.ifaddresses(interface)[netifaces.AF_INET]
        for ipv4_address in ipv4_addresses:
            short_addresses.append(ipv4_address['addr'])
    return short_addresses


def get_ipv6_addresses(interface: str) -> List[str]:
    short_addresses = []
    if netifaces.AF_INET6 in netifaces.ifaddresses(interface):
        ipv6_addresses = netifaces.ifaddresses(interface)[netifaces.AF_INET6]
        for ipv6_address in ipv6_addresses:
            # Skip link-local addresses (see https://superuser.com/a/99753 ).
            if '%' not in ipv6_address['addr']:
                short_addresses.append(ipv6_address['addr'])
    return short_addresses


def ips2name(addrs: Iterable[str]) -> str:
    for addr in addrs:
        fqdn = socket.getfqdn(addr)
        domainname = get_ucs_domainname_from_fqdn(fqdn)
        if domainname:
            return domainname
    return ""


def get_ucs_domainname_from_fqdn(fqdn: str) -> str:
    if '.' not in fqdn:
        return ""
    # Only accept domains with a _domaincontroller_master._tcp record, to
    # ensure that this is an UCS domain.
    return find_ucs_domain(fqdn.split('.', 1)[1])
