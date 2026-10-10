# SPDX-FileCopyrightText: 2026 univention-arch-connector contributors
# SPDX-License-Identifier: AGPL-3.0-only

import pytest

from univention_arch_connector import join, join_info

SSSD_CONF = """\
[sssd]
domains = example.com

[domain/example.com]
ldap_uri = ldap://dc.example.com:7389/
ldap_default_authtok = secret
"""


@pytest.fixture
def paths(monkeypatch, tmp_path):
    sssd_conf = tmp_path / 'sssd.conf'
    monkeypatch.setattr(join_info, 'SSSD_CONF', sssd_conf)
    monkeypatch.setattr(join_info, 'JOIN_INFO', tmp_path / 'state' / 'join.json')
    monkeypatch.setattr(join_info, 'RESOLVED_DROP_IN', tmp_path / 'resolved.conf')
    monkeypatch.setattr(join_info, 'NETWORKMANAGER_DROP_IN', tmp_path / 'nm.conf')
    monkeypatch.setattr(join_info.socket, 'gethostbyname', lambda host: '192.0.2.10')
    return tmp_path


def test_not_joined(paths):
    assert join_info.load() is None
    assert join.already_joined_notice() is None


def test_saved_join_is_loaded_without_secrets(paths):
    (paths / 'sssd.conf').write_text(SSSD_CONF)
    join_info.save('example.com', 'dc.example.com', '192.0.2.10', 'SHA256:abc', 'Administrator', True, False)

    info = join_info.load()
    assert info['username'] == 'Administrator' and info['dc_fingerprint'] == 'SHA256:abc'
    assert info['force_ucs_dns'] is True and info['joined_at']
    assert 'secret' not in (paths / 'state' / 'join.json').read_text()
    notice = join.already_joined_notice()
    assert 'already a member of the domain example.com (domain controller dc.example.com) on ' in notice

    join_info.remove()
    assert not (paths / 'state' / 'join.json').exists()


def test_older_join_is_derived_from_the_configuration(paths):
    (paths / 'sssd.conf').write_text(SSSD_CONF)
    (paths / 'resolved.conf').write_text('[Resolve]\n')

    info = join_info.load()
    assert info['domain'] == 'example.com' and info['dc_host'] == 'dc.example.com'
    assert info['dc_ip'] == '192.0.2.10' and info['force_ucs_dns'] is True
    assert info['username'] is None and info['joined_at'] is None
    assert join.already_joined_notice().startswith(
        'This computer is already a member of the domain example.com (domain controller dc.example.com). '
    )
