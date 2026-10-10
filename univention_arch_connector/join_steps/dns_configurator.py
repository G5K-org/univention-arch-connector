#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2025 univention-arch-connector contributors
# SPDX-License-Identifier: AGPL-3.0-only
#
# New module, replacing upstream's `dns_configurator.py`. Upstream juggles
# nmcli (version-gated), a legacy "Trusty" dhclient+resolvconf chain, and a
# defined-but-unused systemd-resolved backend. On Arch only three backends
# are realistic, tried in this priority order: systemd-resolved (the
# backend `utils/domain.py`'s own domain auto-detection already assumes is
# present), NetworkManager, and a plain /etc/resolv.conf fallback. The
# legacy Debian chain is dropped entirely. See ../../NOTICE.md. Only used
# when --force-ucs-dns is passed; otherwise the existing DNS setup is
# trusted to already resolve the UCS domain.

import logging
import re
import shutil
import subprocess
from pathlib import Path
from typing import List, Optional

import dns.resolver

from univention_arch_connector.distributions import DcResolveException
from univention_arch_connector.utils.backup import Backup
from univention_arch_connector.utils.general import execute_as_root

userinfo_logger = logging.getLogger('userinfo')

RESOLV_CONF = Path('/etc/resolv.conf')


def _is_active(unit: str) -> bool:
    return subprocess.call(
        ['systemctl', 'is-active', '--quiet', unit],
    ) == 0


def _default_interface() -> Optional[str]:
    try:
        output = subprocess.check_output(['ip', 'route', 'show', 'default'], text=True)
    except subprocess.CalledProcessError:
        return None
    match = re.search(r'\bdev\s+(\S+)', output)
    return match.group(1) if match else None


class DnsConfigurator:
    @execute_as_root
    def backup(self, backup: Backup) -> None:
        backup.backup_file(str(RESOLV_CONF))

    def configure_dns(self, nameservers: List[str], domain: str) -> None:
        if shutil.which('resolvectl') and _is_active('systemd-resolved'):
            self._configure_via_resolvectl(nameservers, domain)
        elif shutil.which('nmcli') and _is_active('NetworkManager'):
            self._configure_via_nmcli(nameservers, domain)
        else:
            self._configure_via_resolv_conf(nameservers, domain)

    @execute_as_root
    def _configure_via_resolvectl(self, nameservers: List[str], domain: str) -> None:
        interface = _default_interface()
        if not interface:
            userinfo_logger.warning('Could not determine the default network interface; falling back to /etc/resolv.conf')
            self._configure_via_resolv_conf(nameservers, domain)
            return
        userinfo_logger.info('Configuring DNS via systemd-resolved on %s', interface)
        subprocess.check_output(['resolvectl', 'dns', interface, *nameservers], stderr=subprocess.STDOUT)
        subprocess.check_output(['resolvectl', 'domain', interface, '~%s' % (domain,), domain], stderr=subprocess.STDOUT)

    @execute_as_root
    def _configure_via_nmcli(self, nameservers: List[str], domain: str) -> None:
        interface = _default_interface()
        connection = None
        if interface:
            try:
                connection = subprocess.check_output(
                    ['nmcli', '-g', 'GENERAL.CONNECTION', 'device', 'show', interface],
                    text=True, stderr=subprocess.STDOUT,
                ).strip()
            except subprocess.CalledProcessError:
                connection = None
        if not connection:
            userinfo_logger.warning('Could not determine the active NetworkManager connection; falling back to /etc/resolv.conf')
            self._configure_via_resolv_conf(nameservers, domain)
            return
        userinfo_logger.info('Configuring DNS via NetworkManager connection "%s"', connection)
        subprocess.check_output(
            ['nmcli', 'con', 'mod', connection,
             'ipv4.dns', ' '.join(nameservers),
             'ipv4.ignore-auto-dns', 'yes',
             'ipv4.dns-search', domain],
            stderr=subprocess.STDOUT,
        )
        subprocess.check_output(['nmcli', 'con', 'up', connection], stderr=subprocess.STDOUT)

    @execute_as_root
    def _configure_via_resolv_conf(self, nameservers: List[str], domain: str) -> None:
        userinfo_logger.info('Configuring DNS by writing %s directly', RESOLV_CONF)
        userinfo_logger.warning(
            '%s was written directly; if NetworkManager or systemd-resolved manage this '
            'system, they may overwrite it again later.', RESOLV_CONF,
        )
        content = ''.join('nameserver %s\n' % (ns,) for ns in nameservers)
        content += 'search %s\n' % (domain,)
        RESOLV_CONF.write_text(content)

    def check_if_dns_works(self, domain: str) -> None:
        resolver = dns.resolver.Resolver()
        try:
            resolver.resolve('_domaincontroller_master._tcp.%s.' % (domain,), 'SRV')
        except Exception as exc:
            raise DcResolveException(
                "DNS was configured, but '_domaincontroller_master._tcp.%s' still doesn't resolve: %s"
                % (domain, exc)
            )
