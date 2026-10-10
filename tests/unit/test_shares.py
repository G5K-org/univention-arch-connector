# SPDX-FileCopyrightText: 2026 univention-arch-connector contributors
# SPDX-License-Identifier: AGPL-3.0-only

from pathlib import Path
from xml.etree import ElementTree

import pytest

from univention_arch_connector import shares
from univention_arch_connector.distributions import DomainJoinException
from univention_arch_connector.join_steps import pam_configurator as pc
from univention_arch_connector.join_steps import sssd_configurator as sc

# Shaped like Arch's pam_mount package default.
PAM_MOUNT_CONF = """\
<?xml version="1.0" encoding="utf-8" ?>
<!DOCTYPE pam_mount SYSTEM "pam_mount.conf.xml.dtd">
<pam_mount>
<debug enable="0" />
<mntoptions require="nosuid,nodev" />
<logout wait="0" hup="no" term="no" kill="no" />
<mkmountpoint enable="1" remove="true" />
</pam_mount>
"""

SHARE = shares.Share('arch-test', 'dc.example.com')
HOME = shares.HomeShare('alice', 'files.example.com', 'homes/alice')


@pytest.fixture
def pam_mount_conf(monkeypatch, tmp_path: Path) -> Path:
    path = tmp_path / 'pam_mount.conf.xml'
    path.write_text(PAM_MOUNT_CONF)
    monkeypatch.setattr(shares, 'PAM_MOUNT_CONF', path)
    return path


@pytest.mark.parametrize('unc, expected', [
    (r'\\files.example.com\alice', ('files.example.com', 'alice')),
    (r'\\files.example.com\homes\alice', ('files.example.com', 'homes/alice')),
    ('//files.example.com/homes/alice/', ('files.example.com', 'homes/alice')),
    (r'\\files.example.com', None),
])
def test_parse_unc(unc, expected):
    assert shares.parse_unc(unc) == expected


def test_volumes_for_shares_and_home_shares():
    shares_volume, home_volume = (
        ElementTree.fromstring(line) for line in shares.volume_lines([SHARE], [HOME], 'Domänen-Benutzer')
    )
    assert shares_volume.attrib == {
        'sgrp': 'Domänen-Benutzer', 'fstype': 'cifs', 'server': 'dc.example.com', 'path': 'arch-test',
        'mountpoint': '~/Freigaben/arch-test', 'options': shares.MOUNT_OPTIONS,
    }
    assert home_volume.attrib['user'] == 'alice'
    assert home_volume.attrib['path'] == 'homes/alice'
    assert home_volume.attrib['mountpoint'] == '~/Freigaben/homes'
    assert 'sec=krb5' in shares.MOUNT_OPTIONS and 'cruid=%(USERUID)' in shares.MOUNT_OPTIONS


def test_volume_attributes_are_escaped():
    line = shares.volume_lines([shares.Share('a"b&c', 'dc')], [], 'G<1>')[0]
    volume = ElementTree.fromstring(line)
    assert volume.attrib['path'] == 'a"b&c' and volume.attrib['sgrp'] == 'G<1>'


def test_write_replace_and_remove_volumes(pam_mount_conf):
    shares._write_volumes_impl(shares.volume_lines([SHARE], [], 'Domain Users'))
    content = pam_mount_conf.read_text()
    assert content.index(shares.BEGIN) < content.index('</pam_mount>')
    assert shares.configured_share_names() == ['arch-test']

    shares._write_volumes_impl(shares.volume_lines([shares.Share('other', 'dc')], [HOME], 'Domain Users'))
    assert pam_mount_conf.read_text().count(shares.BEGIN) == 1
    assert shares.configured_share_names() == ['other']  # home shares aren't listed

    shares._write_volumes_impl([])
    assert pam_mount_conf.read_text() == PAM_MOUNT_CONF


def test_invalid_xml_is_never_written(pam_mount_conf):
    with pytest.raises(ElementTree.ParseError):
        shares._write_volumes_impl(['<volume broken\n'])
    assert pam_mount_conf.read_text() == PAM_MOUNT_CONF


def test_missing_packages_are_reported(monkeypatch, tmp_path):
    monkeypatch.setattr(shares.shutil, 'which', lambda program: None)
    monkeypatch.setattr(shares, 'PAM_MOUNT_MODULE', tmp_path / 'missing.so')
    with pytest.raises(DomainJoinException, match='pacman -S cifs-utils keyutils pam_mount'):
        shares.check_requirements()


def test_unknown_share_names_are_rejected(monkeypatch):
    monkeypatch.setattr(shares, 'check_requirements', lambda: None)
    monkeypatch.setattr(shares, 'list_shares', lambda: [SHARE])
    with pytest.raises(DomainJoinException, match='Unknown share.*nope.*Available: arch-test'):
        shares.setup_shares(['nope'])


def test_ccache_template_is_added_to_older_sssd_conf(monkeypatch, tmp_path):
    sssd_conf = tmp_path / 'sssd.conf'
    sssd_conf.write_text('[domain/example.com]\nkrb5_realm = EXAMPLE.COM\ncache_credentials = true\n')
    monkeypatch.setattr(sc, 'SSSD_CONF', sssd_conf)
    monkeypatch.setattr(sc.subprocess, 'check_output', lambda *a, **k: b'')

    for _ in range(2):
        sc.SssdConfigurator.ensure_default_ccache_location.__wrapped__(sc.SssdConfigurator())

    assert sssd_conf.read_text() == (
        '[domain/example.com]\nkrb5_realm = EXAMPLE.COM\n'
        'krb5_ccname_template = FILE:/tmp/krb5cc_%U\ncache_credentials = true\n'
    )


def test_pam_mount_goes_after_mkhomedir(monkeypatch, tmp_path):
    from tests.unit.test_pam_configurator import REAL_SYSTEM_LOGIN
    system_login = tmp_path / 'system-login'
    system_login.write_text(REAL_SYSTEM_LOGIN)
    monkeypatch.setattr(pc, 'SYSTEM_LOGIN', system_login)
    pc.PamConfigurator.configure_home_dir_creation.__wrapped__(pc.PamConfigurator())

    pc.PamConfigurator.enable_pam_mount.__wrapped__(pc.PamConfigurator())

    lines = system_login.read_text().splitlines()
    mkhomedir = lines.index(pc.MKHOMEDIR_LINE.rstrip('\n'))
    assert lines[mkhomedir + 1] == '# END %s' % (pc.MKHOMEDIR_MARKER,)
    assert lines[mkhomedir + 3] == pc.PAM_MOUNT_LINE.rstrip('\n')
    assert 'disable_interactive' in pc.PAM_MOUNT_LINE

    pc.PamConfigurator.disable_pam_mount.__wrapped__(pc.PamConfigurator())
    assert 'pam_mount' not in system_login.read_text()


SSSD_CONF_TEXT = """\
[domain/example.com]
ldap_uri = ldap://dc.example.com:7389/
ldap_search_base = dc=example,dc=com
krb5_realm = EXAMPLE.COM
cache_credentials = true
enumerate = false
"""


def test_domain_users_listing_toggles_and_survives_rejoin_template(monkeypatch, tmp_path):
    sssd_conf = tmp_path / 'sssd.conf'
    sssd_conf.write_text(SSSD_CONF_TEXT)
    monkeypatch.setattr(sc, 'SSSD_CONF', sssd_conf)
    configurator = sc.SssdConfigurator()
    set_listed = sc.SssdConfigurator.set_domain_users_listed.__wrapped__
    listed = sc.SssdConfigurator.domain_users_listed.__wrapped__

    assert not listed(configurator)
    set_listed(configurator, True, restart=False)
    set_listed(configurator, True, restart=False)  # idempotent
    content = sssd_conf.read_text()
    assert 'enumerate = true\n' in content
    assert content.count('ldap_user_search_base') == 1
    assert ('ldap_user_search_base = dc=example,dc=com?subtree?(&(objectClass=inetOrgPerson)'
            '(!(univentionObjectFlag=hidden))(!(shadowExpire=1)))\n') in content
    assert listed(configurator)

    set_listed(configurator, False, restart=False)
    assert sssd_conf.read_text() == SSSD_CONF_TEXT


def test_machine_password_is_replaced_in_sssd_conf(monkeypatch, tmp_path):
    sssd_conf = tmp_path / 'sssd.conf'
    sssd_conf.write_text('[domain/example.com]\nldap_default_authtok = old\nkrb5_realm = EXAMPLE.COM\n')
    monkeypatch.setattr(sc, 'SSSD_CONF', sssd_conf)
    monkeypatch.setattr(sc.subprocess, 'check_output', lambda *a, **k: b'')

    sc.SssdConfigurator.update_machine_password.__wrapped__(sc.SssdConfigurator(), 'n3w;#\\')

    assert sssd_conf.read_text() == '[domain/example.com]\nldap_default_authtok = n3w;#\\\nkrb5_realm = EXAMPLE.COM\n'
