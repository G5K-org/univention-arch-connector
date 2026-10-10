#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2025 univention-arch-connector contributors
# SPDX-License-Identifier: AGPL-3.0-only
#
# New module, replacing upstream's Debian-only `pam_configurator.py` (which
# relies on `pam-auth-update` and `/usr/share/pam-configs/*`, a mechanism
# Arch does not have). Instead this edits `/etc/pam.d/system-login` and
# `/etc/security/group.conf` directly, using idempotent, clearly delimited
# marker blocks so the change can be detected, re-applied safely, and
# surgically removed again by the --leave-domain path. See ../../NOTICE.md.
#
# `/etc/pam.d/system-login` is provided by Arch's `pambase` package and is
# `include`d by every interactive login service on the system (console
# `login`, `su -l`, and - via their own PAM service files including
# `system-login` - SDDM, GDM and LightDM), so editing it once covers all of
# them without touching desktop-environment-specific PAM files.

import logging
import re
from pathlib import Path
from typing import List

from univention_arch_connector.utils.backup import Backup
from univention_arch_connector.utils.general import execute_as_root

userinfo_logger = logging.getLogger('userinfo')

SYSTEM_LOGIN = Path('/etc/pam.d/system-login')
GROUP_CONF = Path('/etc/security/group.conf')

MKHOMEDIR_MARKER = 'univention-arch-connector (pam_mkhomedir)'
PAM_GROUP_MARKER = 'univention-arch-connector (pam_group)'

# `optional`, not `required`: a failure in either module must never lock a
# domain user out of login.
MKHOMEDIR_LINE = 'session    optional    pam_mkhomedir.so umask=0022 skel=/etc/skel\n'
PAM_GROUP_LINE = 'auth       optional    pam_group.so use_first_pass\n'

GROUP_CONF_LINE = '*;*;*;Al0000-2400;audio,cdrom,dialout,floppy,plugdev,adm\n'


def _insert_marked_block(path: Path, marker_name: str, anchor_pattern: str, block_lines: List[str]) -> None:
    """Idempotently insert ``block_lines`` right after the first line
    matching ``anchor_pattern``, wrapped in ``# BEGIN``/``# END`` markers.
    A no-op if the marker is already present. Falls back to appending at
    end-of-file (with a warning) if the anchor can't be found, rather than
    silently doing nothing.
    """
    begin = '# BEGIN %s\n' % (marker_name,)
    end = '# END %s\n' % (marker_name,)
    lines = path.read_text().splitlines(keepends=True)

    if any(line.rstrip('\n') == begin.rstrip('\n') for line in lines):
        return

    anchor_re = re.compile(anchor_pattern)
    insert_at = None
    for i, line in enumerate(lines):
        if anchor_re.match(line.rstrip('\n')):
            insert_at = i + 1
            break
    if insert_at is None:
        userinfo_logger.warning(
            "Anchor line matching %r not found in %s; appending block at end of file instead",
            anchor_pattern, path,
        )
        insert_at = len(lines)

    new_block = [begin, *block_lines, end]
    lines[insert_at:insert_at] = new_block
    path.write_text(''.join(lines))


def _remove_marked_block(path: Path, marker_name: str) -> None:
    if not path.exists():
        return
    begin = '# BEGIN %s' % (marker_name,)
    end = '# END %s' % (marker_name,)
    lines = path.read_text().splitlines(keepends=True)
    out: List[str] = []
    inside = False
    for line in lines:
        stripped = line.rstrip('\n')
        if stripped == begin:
            inside = True
            continue
        if stripped == end:
            inside = False
            continue
        if not inside:
            out.append(line)
    path.write_text(''.join(out))


class PamConfigurator:
    @execute_as_root
    def backup(self, backup: Backup) -> None:
        backup.backup_file(str(SYSTEM_LOGIN))
        backup.backup_file(str(GROUP_CONF))

    def setup_pam(self) -> None:
        self.configure_home_dir_creation()
        self.add_users_to_required_system_groups()

    @execute_as_root
    def configure_home_dir_creation(self) -> None:
        userinfo_logger.info('Enabling automatic home directory creation (pam_mkhomedir) in %s', SYSTEM_LOGIN)
        _insert_marked_block(
            SYSTEM_LOGIN,
            MKHOMEDIR_MARKER,
            anchor_pattern=r'^session\s+include\s+system-auth\s*$',
            block_lines=[MKHOMEDIR_LINE],
        )

    @execute_as_root
    def add_users_to_required_system_groups(self) -> None:
        self._add_group_conf_line()
        self._insert_pam_group_block()

    def _add_group_conf_line(self) -> None:
        if self._group_conf_already_ok():
            return
        userinfo_logger.info('Adding supplementary groups for interactive logins to %s', GROUP_CONF)
        with open(GROUP_CONF, 'a') as groups_file:
            groups_file.write(GROUP_CONF_LINE)

    def _group_conf_already_ok(self) -> bool:
        with open(GROUP_CONF) as groups_file:
            return any(line.rstrip('\n') == GROUP_CONF_LINE.rstrip('\n') for line in groups_file)

    def _insert_pam_group_block(self) -> None:
        userinfo_logger.info('Enabling pam_group (%s) in %s', GROUP_CONF, SYSTEM_LOGIN)
        _insert_marked_block(
            SYSTEM_LOGIN,
            PAM_GROUP_MARKER,
            anchor_pattern=r'^auth\s+include\s+system-auth\s*$',
            block_lines=[PAM_GROUP_LINE],
        )

    @execute_as_root
    def remove(self) -> None:
        """Surgically strip our marker blocks, leaving everything else the
        user may have changed in these files untouched. Used by
        --leave-domain in preference to a full restore-from-backup.
        """
        userinfo_logger.info('Removing univention-arch-connector PAM configuration from %s', SYSTEM_LOGIN)
        _remove_marked_block(SYSTEM_LOGIN, MKHOMEDIR_MARKER)
        _remove_marked_block(SYSTEM_LOGIN, PAM_GROUP_MARKER)
        self._remove_group_conf_line()

    def _remove_group_conf_line(self) -> None:
        if not GROUP_CONF.exists():
            return
        lines = GROUP_CONF.read_text().splitlines(keepends=True)
        new_lines = [line for line in lines if line.rstrip('\n') != GROUP_CONF_LINE.rstrip('\n')]
        if new_lines != lines:
            userinfo_logger.info('Removing univention-arch-connector line from %s', GROUP_CONF)
            GROUP_CONF.write_text(''.join(new_lines))
