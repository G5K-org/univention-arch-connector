#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2025 univention-arch-connector contributors
# SPDX-License-Identifier: AGPL-3.0-only
#
# New module, replacing upstream's `dns_configurator.py`. Upstream juggles
# nmcli (version-gated), a legacy "Trusty" dhclient+resolvconf chain, and a
# defined-but-unused systemd-resolved backend. On Arch only three backends
# are realistic, tried in this priority order: systemd-resolved (if it
# actually serves /etc/resolv.conf), NetworkManager, and a plain
# /etc/resolv.conf fallback. The legacy Debian chain is dropped entirely.
#
# All three write configuration files rather than runtime settings
# (`resolvectl dns` is forgotten on reboot, `nmcli con mod` isn't covered by
# the backup), so the change persists, and --leave-domain and rollback undo
# it by restoring/removing the files. See ../../NOTICE.md. Only used when
# --force-ucs-dns is passed; otherwise the existing DNS setup is trusted to
# already resolve the UCS domain.

import logging
import shutil
import subprocess
from pathlib import Path
from typing import List

import dns.resolver

from univention_arch_connector.distributions import DcResolveException
from univention_arch_connector.utils.backup import Backup
from univention_arch_connector.utils.general import execute_as_root

userinfo_logger = logging.getLogger('userinfo')

RESOLV_CONF = Path('/etc/resolv.conf')
RESOLVED_DROP_IN = Path('/etc/systemd/resolved.conf.d/univention-arch-connector.conf')
NETWORKMANAGER_DROP_IN = Path('/etc/NetworkManager/conf.d/univention-arch-connector-dns.conf')


def _is_active(unit: str) -> bool:
    return subprocess.call(
        ['systemctl', 'is-active', '--quiet', unit],
    ) == 0


def _resolved_serves_resolv_conf() -> bool:
    """Whether DNS lookups actually go through systemd-resolved: it's
    running and /etc/resolv.conf points at its stub (or full) resolver.
    """
    if not _is_active('systemd-resolved'):
        return False
    try:
        if RESOLV_CONF.is_symlink() and str(RESOLV_CONF.resolve()).startswith('/run/systemd/resolve/'):
            return True
        return any(
            line.split()[:2] == ['nameserver', '127.0.0.53'] for line in RESOLV_CONF.read_text().splitlines()
        )
    except OSError:
        return False


class DnsConfigurator:
    @execute_as_root
    def backup(self, backup: Backup) -> None:
        backup.backup_file(str(RESOLV_CONF))
        backup.backup_file(str(RESOLVED_DROP_IN))
        backup.backup_file(str(NETWORKMANAGER_DROP_IN))

    def configure_dns(self, nameservers: List[str], domain: str) -> None:
        if _resolved_serves_resolv_conf():
            self._configure_via_resolved(nameservers, domain)
        elif shutil.which('nmcli') and _is_active('NetworkManager'):
            self._configure_via_networkmanager(nameservers, domain)
        else:
            self._configure_via_resolv_conf(nameservers, domain)

    @execute_as_root
    def _configure_via_resolved(self, nameservers: List[str], domain: str) -> None:
        # Route (and search) only the UCS domain to the DC; other lookups
        # keep using the existing servers.
        userinfo_logger.info('Configuring DNS via systemd-resolved in %s', RESOLVED_DROP_IN)
        RESOLVED_DROP_IN.parent.mkdir(parents=True, exist_ok=True)
        RESOLVED_DROP_IN.write_text(
            '# Written by univention-arch-connector (--force-ucs-dns)\n'
            '[Resolve]\n'
            'DNS=%s\n'
            'Domains=%s\n' % (' '.join(nameservers), domain)
        )
        subprocess.check_output(['systemctl', 'restart', 'systemd-resolved'], stderr=subprocess.STDOUT)

    @execute_as_root
    def _configure_via_networkmanager(self, nameservers: List[str], domain: str) -> None:
        # Without systemd-resolved, NetworkManager can't split DNS by
        # domain, so all lookups go to the DC, like upstream.
        userinfo_logger.info('Configuring DNS via NetworkManager in %s', NETWORKMANAGER_DROP_IN)
        NETWORKMANAGER_DROP_IN.parent.mkdir(parents=True, exist_ok=True)
        NETWORKMANAGER_DROP_IN.write_text(
            '# Written by univention-arch-connector (--force-ucs-dns)\n'
            '[global-dns]\n'
            'searches=%s\n'
            '\n'
            '[global-dns-domain-*]\n'
            'servers=%s\n' % (domain, ','.join(nameservers))
        )
        subprocess.check_output(['nmcli', 'general', 'reload'], stderr=subprocess.STDOUT)

    @execute_as_root
    def _configure_via_resolv_conf(self, nameservers: List[str], domain: str) -> None:
        userinfo_logger.info('Configuring DNS by writing %s directly', RESOLV_CONF)
        userinfo_logger.warning(
            '%s was written directly; if another program manages this file, it may '
            'overwrite it again later.', RESOLV_CONF,
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
