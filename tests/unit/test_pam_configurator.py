# SPDX-FileCopyrightText: 2025 univention-arch-connector contributors
# SPDX-License-Identifier: AGPL-3.0-only

from pathlib import Path

from univention_arch_connector.join_steps import pam_configurator as pc

# Captured from a real Arch/CachyOS install's pambase package, 2025-10.
REAL_SYSTEM_LOGIN = """\
#%PAM-1.0

auth       required   pam_shells.so
auth       requisite  pam_nologin.so
auth       include    system-auth

account    required   pam_access.so
account    required   pam_nologin.so
account    include    system-auth

password   include    system-auth

session    optional   pam_loginuid.so
session    optional   pam_keyinit.so       force revoke
session    include    system-auth
session    optional   pam_lastlog2.so      silent
session    optional   pam_motd.so
session    optional   pam_mail.so          dir=/var/spool/mail standard quiet
session    optional   pam_umask.so
-session   optional   pam_systemd.so
session    required   pam_env.so
"""


def test_insert_mkhomedir_block_after_session_include(tmp_path: Path) -> None:
    path = tmp_path / 'system-login'
    path.write_text(REAL_SYSTEM_LOGIN)

    pc._insert_marked_block(
        path, pc.MKHOMEDIR_MARKER,
        anchor_pattern=r'^session\s+include\s+system-auth\s*$',
        block_lines=[pc.MKHOMEDIR_LINE],
    )

    lines = path.read_text().splitlines()
    session_include_idx = lines.index('session    include    system-auth')
    assert lines[session_include_idx + 1] == '# BEGIN %s' % (pc.MKHOMEDIR_MARKER,)
    assert lines[session_include_idx + 2] == pc.MKHOMEDIR_LINE.rstrip('\n')
    assert lines[session_include_idx + 3] == '# END %s' % (pc.MKHOMEDIR_MARKER,)
    # Nothing else in the file was disturbed.
    assert lines[0] == '#%PAM-1.0'
    assert lines[-1] == 'session    required   pam_env.so'


def test_insert_pam_group_block_after_auth_include(tmp_path: Path) -> None:
    path = tmp_path / 'system-login'
    path.write_text(REAL_SYSTEM_LOGIN)

    pc._insert_marked_block(
        path, pc.PAM_GROUP_MARKER,
        anchor_pattern=r'^auth\s+include\s+system-auth\s*$',
        block_lines=[pc.PAM_GROUP_LINE],
    )

    lines = path.read_text().splitlines()
    auth_include_idx = lines.index('auth       include    system-auth')
    assert lines[auth_include_idx + 1] == '# BEGIN %s' % (pc.PAM_GROUP_MARKER,)
    assert lines[auth_include_idx + 2] == pc.PAM_GROUP_LINE.rstrip('\n')
    assert lines[auth_include_idx + 3] == '# END %s' % (pc.PAM_GROUP_MARKER,)


def test_insertion_is_idempotent(tmp_path: Path) -> None:
    path = tmp_path / 'system-login'
    path.write_text(REAL_SYSTEM_LOGIN)

    for _ in range(3):
        pc._insert_marked_block(
            path, pc.MKHOMEDIR_MARKER,
            anchor_pattern=r'^session\s+include\s+system-auth\s*$',
            block_lines=[pc.MKHOMEDIR_LINE],
        )

    content = path.read_text()
    assert content.count('# BEGIN %s' % (pc.MKHOMEDIR_MARKER,)) == 1
    assert content.count(pc.MKHOMEDIR_LINE.rstrip('\n')) == 1


def test_remove_restores_original_byte_for_byte(tmp_path: Path) -> None:
    path = tmp_path / 'system-login'
    path.write_text(REAL_SYSTEM_LOGIN)

    pc._insert_marked_block(
        path, pc.MKHOMEDIR_MARKER,
        anchor_pattern=r'^session\s+include\s+system-auth\s*$',
        block_lines=[pc.MKHOMEDIR_LINE],
    )
    pc._insert_marked_block(
        path, pc.PAM_GROUP_MARKER,
        anchor_pattern=r'^auth\s+include\s+system-auth\s*$',
        block_lines=[pc.PAM_GROUP_LINE],
    )
    assert path.read_text() != REAL_SYSTEM_LOGIN

    pc._remove_marked_block(path, pc.MKHOMEDIR_MARKER)
    pc._remove_marked_block(path, pc.PAM_GROUP_MARKER)

    assert path.read_text() == REAL_SYSTEM_LOGIN


def test_remove_is_a_noop_when_marker_absent(tmp_path: Path) -> None:
    path = tmp_path / 'system-login'
    path.write_text(REAL_SYSTEM_LOGIN)

    pc._remove_marked_block(path, pc.MKHOMEDIR_MARKER)

    assert path.read_text() == REAL_SYSTEM_LOGIN


def test_missing_anchor_appends_at_end_of_file_with_warning(tmp_path: Path) -> None:
    path = tmp_path / 'system-login'
    path.write_text('#%PAM-1.0\n')

    pc._insert_marked_block(
        path, pc.MKHOMEDIR_MARKER,
        anchor_pattern=r'^session\s+include\s+system-auth\s*$',
        block_lines=[pc.MKHOMEDIR_LINE],
    )

    lines = path.read_text().splitlines()
    assert lines[-3] == '# BEGIN %s' % (pc.MKHOMEDIR_MARKER,)


def test_group_conf_append_idempotent(monkeypatch, tmp_path: Path) -> None:
    group_conf = tmp_path / 'group.conf'
    group_conf.write_text('# comment only\n')
    monkeypatch.setattr(pc, 'GROUP_CONF', group_conf)

    configurator = pc.PamConfigurator()
    configurator._add_group_conf_line()
    configurator._add_group_conf_line()

    content = group_conf.read_text()
    assert content.count(pc.GROUP_CONF_LINE.rstrip('\n')) == 1
