# SPDX-FileCopyrightText: 2025 univention-arch-connector contributors
# SPDX-License-Identifier: AGPL-3.0-only

from unittest.mock import MagicMock

from univention_arch_connector.join_steps import dns_configurator as dc


def test_default_interface_parses_ip_route_output(monkeypatch):
    monkeypatch.setattr(
        dc.subprocess, 'check_output',
        lambda *a, **k: 'default via 192.168.1.1 dev wlan0 proto dhcp metric 600 \n',
    )
    assert dc._default_interface() == 'wlan0'


def test_default_interface_returns_none_on_failure(monkeypatch):
    def raise_error(*a, **k):
        raise dc.subprocess.CalledProcessError(1, 'ip')
    monkeypatch.setattr(dc.subprocess, 'check_output', raise_error)
    assert dc._default_interface() is None


def test_configure_dns_prefers_resolvectl_when_resolved_active(monkeypatch):
    monkeypatch.setattr(dc.shutil, 'which', lambda name: '/usr/bin/%s' % (name,))
    monkeypatch.setattr(dc, '_is_active', lambda unit: unit == 'systemd-resolved')

    configurator = dc.DnsConfigurator()
    configurator._configure_via_resolvectl = MagicMock()
    configurator._configure_via_nmcli = MagicMock()
    configurator._configure_via_resolv_conf = MagicMock()

    configurator.configure_dns(['10.0.0.1'], 'example.test')

    configurator._configure_via_resolvectl.assert_called_once_with(['10.0.0.1'], 'example.test')
    configurator._configure_via_nmcli.assert_not_called()
    configurator._configure_via_resolv_conf.assert_not_called()


def test_configure_dns_falls_back_to_nmcli_when_resolved_inactive(monkeypatch):
    monkeypatch.setattr(dc.shutil, 'which', lambda name: '/usr/bin/%s' % (name,))
    monkeypatch.setattr(dc, '_is_active', lambda unit: unit == 'NetworkManager')

    configurator = dc.DnsConfigurator()
    configurator._configure_via_resolvectl = MagicMock()
    configurator._configure_via_nmcli = MagicMock()
    configurator._configure_via_resolv_conf = MagicMock()

    configurator.configure_dns(['10.0.0.1'], 'example.test')

    configurator._configure_via_nmcli.assert_called_once_with(['10.0.0.1'], 'example.test')
    configurator._configure_via_resolvectl.assert_not_called()
    configurator._configure_via_resolv_conf.assert_not_called()


def test_configure_dns_falls_back_to_resolv_conf_when_nothing_active(monkeypatch):
    monkeypatch.setattr(dc.shutil, 'which', lambda name: None)
    monkeypatch.setattr(dc, '_is_active', lambda unit: False)

    configurator = dc.DnsConfigurator()
    configurator._configure_via_resolvectl = MagicMock()
    configurator._configure_via_nmcli = MagicMock()
    configurator._configure_via_resolv_conf = MagicMock()

    configurator.configure_dns(['10.0.0.1'], 'example.test')

    configurator._configure_via_resolv_conf.assert_called_once_with(['10.0.0.1'], 'example.test')
    configurator._configure_via_resolvectl.assert_not_called()
    configurator._configure_via_nmcli.assert_not_called()


def test_check_if_dns_works_raises_when_srv_record_missing(monkeypatch):
    def raise_error(*a, **k):
        raise Exception('NXDOMAIN')
    resolver_instance = MagicMock()
    resolver_instance.resolve.side_effect = raise_error
    monkeypatch.setattr(dc.dns.resolver, 'Resolver', lambda: resolver_instance)

    try:
        dc.DnsConfigurator().check_if_dns_works('example.test')
    except dc.DcResolveException:
        pass
    else:
        raise AssertionError('expected DcResolveException')
