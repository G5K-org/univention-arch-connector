# SPDX-FileCopyrightText: 2026 univention-arch-connector contributors
# SPDX-License-Identifier: AGPL-3.0-only

import shutil
import subprocess
from pathlib import Path

import pytest

from univention_arch_connector import admin_group
from univention_arch_connector.distributions import DomainJoinException


# Shaped like the end of Arch's sudo.conf.
SUDO_CONF = '''\
# User groups:
#   Set group_source static|dynamic|adaptive
#Set group_source static
'''


@pytest.fixture
def paths(monkeypatch, tmp_path: Path):
    sudoers = tmp_path / 'sudoers.d' / '50-univention-arch-connector'
    sudoers.parent.mkdir()
    polkit = tmp_path / 'rules.d' / '49-univention-arch-connector.rules'
    polkit.parent.mkdir()
    monkeypatch.setattr(admin_group, 'SUDOERS_FILE', sudoers)
    monkeypatch.setattr(admin_group, 'POLKIT_RULE', polkit)
    sudo_conf = tmp_path / 'sudo.conf'
    sudo_conf.write_text(SUDO_CONF)
    monkeypatch.setattr(admin_group, 'SUDO_CONF', sudo_conf)
    monkeypatch.setattr(admin_group, 'check_requirements', lambda: None)
    monkeypatch.setattr(admin_group, 'group_exists_in_ucs', lambda group: True)
    return sudoers, polkit, sudo_conf


@pytest.fixture
def fake_visudo(monkeypatch):
    calls = []

    def run(cmd, **kwargs):
        calls.append(Path(cmd[-1]).read_text())
        return subprocess.CompletedProcess(cmd, 0, '', '')
    monkeypatch.setattr(admin_group.subprocess, 'run', run)
    return calls


def test_sudoers_rule_escapes_spaces():
    content = admin_group.sudoers_content('Linux Admins')
    assert '%Linux\\ Admins ALL=(ALL:ALL) ALL\n' in content
    assert '# admin-group: Linux Admins\n' in content


def test_polkit_rule_keeps_wheel():
    content = admin_group.polkit_content('linux-admins')
    assert 'return ["unix-group:linux-admins", "unix-group:wheel"];' in content


@pytest.mark.parametrize('name', ['', ' admins', 'admins ', 'a,b', 'a:b', 'evil\nALL ALL=(ALL) ALL', '%admins', 'a\\b', 'admins\n'])
def test_rejects_unsafe_group_names(name):
    with pytest.raises(DomainJoinException):
        admin_group.validate_group_name(name)


@pytest.mark.parametrize('name', ['linux-admins', 'Domain Admins', 'admins_2.0'])
def test_accepts_group_names(name):
    admin_group.validate_group_name(name)


def test_setup_and_remove(paths, fake_visudo):
    sudoers, polkit, sudo_conf = paths
    admin_group.setup('Linux Admins')
    assert sudoers.read_text() == admin_group.sudoers_content('Linux Admins')
    assert sudoers.stat().st_mode & 0o777 == 0o440
    assert fake_visudo == [admin_group.sudoers_content('Linux Admins')]
    assert polkit.read_text() == admin_group.polkit_content('Linux Admins')
    assert admin_group.configured_group() == 'Linux Admins'
    assert sudo_conf.read_text().endswith('#Set group_source static\n' + admin_group.SUDO_CONF_MARKER + '\n'
                                          'Set group_source dynamic\n')
    admin_group.setup('Linux Admins')  # re-join
    assert sudo_conf.read_text().count('Set group_source dynamic') == 1

    admin_group.remove()
    assert not sudoers.exists() and not polkit.exists()
    assert sudo_conf.read_text() == SUDO_CONF
    assert admin_group.configured_group() is None


def test_setup_keeps_old_rule_when_visudo_rejects(paths, monkeypatch):
    sudoers, _, _ = paths
    sudoers.write_text('old\n')
    monkeypatch.setattr(admin_group.subprocess, 'run',
                        lambda cmd, **kwargs: subprocess.CompletedProcess(cmd, 1, '', 'syntax error'))
    with pytest.raises(DomainJoinException, match='syntax error'):
        admin_group.setup('admins')
    assert sudoers.read_text() == 'old\n'
    assert [p.name for p in sudoers.parent.iterdir()] == [sudoers.name]


def test_setup_without_polkit(paths, fake_visudo):
    _, polkit, _ = paths
    polkit.parent.rmdir()
    admin_group.setup('admins')
    assert not polkit.exists()


def test_warns_if_group_missing_in_ucs(paths, fake_visudo, monkeypatch, caplog):
    monkeypatch.setattr(admin_group, 'group_exists_in_ucs', lambda group: False)
    admin_group.setup('admins')
    assert "no group 'admins' in UCS" in caplog.text


def test_keeps_group_source_set_by_the_admin(paths, fake_visudo):
    _, _, sudo_conf = paths
    sudo_conf.write_text('Set group_source adaptive\n')
    admin_group.setup('admins')
    admin_group.remove()
    assert sudo_conf.read_text() == 'Set group_source adaptive\n'


@pytest.mark.skipif(not shutil.which('visudo'), reason='sudo not installed')
def test_rule_passes_visudo(tmp_path: Path):
    path = tmp_path / 'rule'
    path.write_text(admin_group.sudoers_content('Domain Admins'))
    subprocess.run(['visudo', '-c', '-q', '-f', str(path)], check=True)
