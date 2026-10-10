# SPDX-FileCopyrightText: 2025 univention-arch-connector contributors
# SPDX-License-Identifier: AGPL-3.0-only

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from univention_arch_connector.join_steps import dns_configurator as dc


def _configurator_with_mocked_backends():
    configurator = dc.DnsConfigurator()
    configurator._configure_via_resolved = MagicMock()
    configurator._configure_via_networkmanager = MagicMock()
    configurator._configure_via_resolv_conf = MagicMock()
    return configurator


def test_configure_dns_prefers_resolved_when_it_serves_resolv_conf(monkeypatch):
    monkeypatch.setattr(dc, '_resolved_serves_resolv_conf', lambda: True)
    configurator = _configurator_with_mocked_backends()

    configurator.configure_dns(['10.0.0.1'], 'example.test')

    configurator._configure_via_resolved.assert_called_once_with(['10.0.0.1'], 'example.test')
    configurator._configure_via_networkmanager.assert_not_called()
    configurator._configure_via_resolv_conf.assert_not_called()


def test_configure_dns_uses_networkmanager_without_resolved(monkeypatch):
    monkeypatch.setattr(dc, '_resolved_serves_resolv_conf', lambda: False)
    monkeypatch.setattr(dc.shutil, 'which', lambda name: '/usr/bin/%s' % (name,))
    monkeypatch.setattr(dc, '_is_active', lambda unit: unit == 'NetworkManager')
    configurator = _configurator_with_mocked_backends()

    configurator.configure_dns(['10.0.0.1'], 'example.test')

    configurator._configure_via_networkmanager.assert_called_once_with(['10.0.0.1'], 'example.test')
    configurator._configure_via_resolved.assert_not_called()


def test_configure_dns_falls_back_to_resolv_conf_when_nothing_active(monkeypatch):
    monkeypatch.setattr(dc, '_resolved_serves_resolv_conf', lambda: False)
    monkeypatch.setattr(dc.shutil, 'which', lambda name: None)
    monkeypatch.setattr(dc, '_is_active', lambda unit: False)
    configurator = _configurator_with_mocked_backends()

    configurator.configure_dns(['10.0.0.1'], 'example.test')

    configurator._configure_via_resolv_conf.assert_called_once_with(['10.0.0.1'], 'example.test')


@pytest.mark.parametrize('content, expected', [
    ('nameserver 127.0.0.53\noptions edns0 trust-ad\n', True),
    ('search example.test\nnameserver 10.1.0.1\n', False),  # e.g. written by Proxmox
])
def test_resolved_serves_resolv_conf_by_content(monkeypatch, tmp_path: Path, content, expected):
    resolv_conf = tmp_path / 'resolv.conf'
    resolv_conf.write_text(content)
    monkeypatch.setattr(dc, 'RESOLV_CONF', resolv_conf)
    monkeypatch.setattr(dc, '_is_active', lambda unit: True)
    assert dc._resolved_serves_resolv_conf() is expected


def test_resolved_not_used_when_inactive(monkeypatch, tmp_path: Path):
    resolv_conf = tmp_path / 'resolv.conf'
    resolv_conf.write_text('nameserver 127.0.0.53\n')
    monkeypatch.setattr(dc, 'RESOLV_CONF', resolv_conf)
    monkeypatch.setattr(dc, '_is_active', lambda unit: False)
    assert dc._resolved_serves_resolv_conf() is False


def test_resolved_drop_in_routes_only_the_domain(monkeypatch, tmp_path: Path):
    drop_in = tmp_path / 'resolved.conf.d' / 'univention-arch-connector.conf'
    monkeypatch.setattr(dc, 'RESOLVED_DROP_IN', drop_in)
    restart = MagicMock()
    monkeypatch.setattr(dc.subprocess, 'check_output', restart)

    dc.DnsConfigurator._configure_via_resolved.__wrapped__(dc.DnsConfigurator(), ['10.0.0.1', '10.0.0.2'], 'example.test')

    lines = drop_in.read_text().splitlines()
    assert '[Resolve]' in lines and 'DNS=10.0.0.1 10.0.0.2' in lines and 'Domains=example.test' in lines
    restart.assert_called_once_with(['systemctl', 'restart', 'systemd-resolved'], stderr=dc.subprocess.STDOUT)


def test_networkmanager_drop_in_sets_global_dns(monkeypatch, tmp_path: Path):
    drop_in = tmp_path / 'conf.d' / 'univention-arch-connector-dns.conf'
    monkeypatch.setattr(dc, 'NETWORKMANAGER_DROP_IN', drop_in)
    reload = MagicMock()
    monkeypatch.setattr(dc.subprocess, 'check_output', reload)

    dc.DnsConfigurator._configure_via_networkmanager.__wrapped__(dc.DnsConfigurator(), ['10.0.0.1', '10.0.0.2'], 'example.test')

    content = drop_in.read_text()
    assert '[global-dns]\nsearches=example.test\n' in content
    assert '[global-dns-domain-*]\nservers=10.0.0.1,10.0.0.2\n' in content
    reload.assert_called_once_with(['nmcli', 'general', 'reload'], stderr=dc.subprocess.STDOUT)


def test_check_if_dns_works_raises_when_srv_record_missing(monkeypatch):
    resolver_instance = MagicMock()
    resolver_instance.resolve.side_effect = Exception('NXDOMAIN')
    monkeypatch.setattr(dc.dns.resolver, 'Resolver', lambda: resolver_instance)

    with pytest.raises(dc.DcResolveException):
        dc.DnsConfigurator().check_if_dns_works('example.test')
