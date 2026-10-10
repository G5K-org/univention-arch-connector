# SPDX-FileCopyrightText: 2026 univention-arch-connector contributors
# SPDX-License-Identifier: AGPL-3.0-only

import pytest

from univention_arch_connector.distributions import DomainJoinException
from univention_arch_connector.utils import general
from univention_arch_connector.utils import host_key as hk

# Throwaway key; FINGERPRINT is what `ssh-keygen -lf` prints for it.
KEY_LINE = '192.0.2.10 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGLTleCOeM7jPObXxDmC3TFVIKVQuMbgaPx+3AtJLHvC'
FINGERPRINT = 'SHA256:3WaiAm4+dTErVc5ar7p7TQluszCsXuWZLX/dBaj2gA0'


@pytest.fixture(autouse=True)
def unpinned(monkeypatch):
    monkeypatch.setattr(general, '_ssh_known_hosts_file', None)
    monkeypatch.setattr(hk, 'scan_host_keys', lambda host: [KEY_LINE])


def _never_asked(host, fingerprints):
    raise AssertionError('should not ask')


def test_fingerprint_matches_ssh_keygen():
    assert hk.fingerprint(KEY_LINE) == FINGERPRINT
    assert hk.describe(KEY_LINE) == 'ED25519 %s' % (FINGERPRINT,)


@pytest.mark.parametrize('given', [FINGERPRINT, FINGERPRINT[len('SHA256:'):], FINGERPRINT + '='])
def test_matching_fingerprint_pins_keys(given):
    hk.pin_host_keys('192.0.2.10', given, _never_asked)
    with open(general._ssh_known_hosts_file) as known_hosts:
        assert known_hosts.read() == KEY_LINE + '\n'


def test_mismatching_fingerprint_is_rejected():
    with pytest.raises(DomainJoinException, match='does not match'):
        hk.pin_host_keys('192.0.2.10', 'SHA256:somethingelse', _never_asked)
    assert general._ssh_known_hosts_file is None


def test_confirmation_is_asked_without_fingerprint():
    asked = []
    hk.pin_host_keys('192.0.2.10', None, lambda host, fps: asked.append((host, fps)) or True)
    assert asked == [('192.0.2.10', ['ED25519 %s' % (FINGERPRINT,)])]
    assert general._ssh_known_hosts_file is not None


def test_declined_confirmation_is_rejected():
    with pytest.raises(DomainJoinException, match='not accepted'):
        hk.pin_host_keys('192.0.2.10', None, lambda host, fps: False)
    assert general._ssh_known_hosts_file is None


def test_no_keys_is_rejected(monkeypatch):
    monkeypatch.setattr(hk, 'scan_host_keys', lambda host: [])
    with pytest.raises(DomainJoinException, match='Could not read the SSH host keys'):
        hk.pin_host_keys('192.0.2.10', None, _never_asked)


def test_ssh_refuses_to_connect_before_pinning():
    with pytest.raises(RuntimeError, match='not been verified'):
        general.ssh('Administrator', 'secret', '192.0.2.10', ['true'])
