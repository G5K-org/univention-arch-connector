# SPDX-FileCopyrightText: 2025 univention-arch-connector contributors
# SPDX-License-Identifier: AGPL-3.0-only

from univention_arch_connector.join_steps import nsswitch_configurator as nc

# Captured from a real Arch/CachyOS install, 2025-10. Note the existing
# `[SUCCESS=merge] systemd` token on the `group:` line, which must survive.
REAL_NSSWITCH_CONF = """\
# Name Service Switch configuration file.
# See nsswitch.conf(5) for details.

passwd: files systemd
group: files [SUCCESS=merge] systemd
shadow: files systemd
gshadow: files systemd

publickey: files

hosts: mymachines resolve [!UNAVAIL=return] files myhostname dns
networks: files

protocols: files
services: files
ethers: files
rpc: files

netgroup: files
"""


def test_add_sss_to_passwd_line() -> None:
    line = 'passwd: files systemd\n'
    result = nc._add_sss_to_line(line, nc.DEFAULT_DATABASES)
    assert result == 'passwd: files systemd sss\n'


def test_add_sss_to_group_line_preserves_success_merge_token() -> None:
    line = 'group: files [SUCCESS=merge] systemd\n'
    result = nc._add_sss_to_line(line, nc.DEFAULT_DATABASES)
    assert result == 'group: files [SUCCESS=merge] systemd sss\n'


def test_add_sss_is_idempotent() -> None:
    line = 'passwd: files systemd sss\n'
    result = nc._add_sss_to_line(line, nc.DEFAULT_DATABASES)
    assert result == line


def test_unrelated_lines_are_untouched() -> None:
    line = 'hosts: mymachines resolve [!UNAVAIL=return] files myhostname dns\n'
    result = nc._add_sss_to_line(line, nc.DEFAULT_DATABASES)
    assert result == line


def test_comment_and_blank_lines_are_untouched() -> None:
    assert nc._add_sss_to_line('# a comment\n', nc.DEFAULT_DATABASES) == '# a comment\n'
    assert nc._add_sss_to_line('\n', nc.DEFAULT_DATABASES) == '\n'


def test_sudoers_only_touched_when_enabled() -> None:
    line = 'sudoers: files\n'
    assert nc._add_sss_to_line(line, nc.DEFAULT_DATABASES) == line
    assert nc._add_sss_to_line(line, nc._databases(enable_sudo=True)) == 'sudoers: files sss\n'


def test_setup_nsswitch_on_real_file_adds_sss_to_exactly_the_right_lines(monkeypatch, tmp_path) -> None:
    path = tmp_path / 'nsswitch.conf'
    path.write_text(REAL_NSSWITCH_CONF)
    monkeypatch.setattr(nc, 'NSSWITCH_CONF', path)

    nc._setup_nsswitch_impl()

    lines = path.read_text().splitlines()
    assert 'passwd: files systemd sss' in lines
    assert 'group: files [SUCCESS=merge] systemd sss' in lines
    assert 'shadow: files systemd sss' in lines
    assert 'gshadow: files systemd' in lines  # untouched - not a target database
    assert 'hosts: mymachines resolve [!UNAVAIL=return] files myhostname dns' in lines  # untouched
    assert 'sudoers: files' not in lines  # wasn't present, and sudo wasn't enabled


def test_setup_nsswitch_is_idempotent(monkeypatch, tmp_path) -> None:
    path = tmp_path / 'nsswitch.conf'
    path.write_text(REAL_NSSWITCH_CONF)
    monkeypatch.setattr(nc, 'NSSWITCH_CONF', path)

    nc._setup_nsswitch_impl()
    once = path.read_text()
    nc._setup_nsswitch_impl()
    twice = path.read_text()

    assert once == twice


def test_remove_restores_original(monkeypatch, tmp_path) -> None:
    path = tmp_path / 'nsswitch.conf'
    path.write_text(REAL_NSSWITCH_CONF)
    monkeypatch.setattr(nc, 'NSSWITCH_CONF', path)

    nc._setup_nsswitch_impl()
    assert path.read_text() != REAL_NSSWITCH_CONF

    nc._remove_nsswitch_impl()
    assert path.read_text() == REAL_NSSWITCH_CONF
