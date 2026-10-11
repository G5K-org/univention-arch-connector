#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 univention-arch-connector contributors
# SPDX-License-Identifier: AGPL-3.0-only
#
# New module, with no upstream equivalent: administrator rights for the
# members of a UCS group (--admin-group at join). Members get full sudo
# rights through a drop-in in /etc/sudoers.d, and count as administrators
# for polkit (KDE/GNOME password prompts) through a rule that keeps the
# default wheel group. Who is a member is managed in UCS only: adding a user
# to the group, or removing them, takes effect on this system once SSSD's
# cache expires (about 2 minutes, see sssd_configurator.py): sudo is
# set to look up the groups on every call (group_source dynamic in
# sudo.conf) instead of using those of the login session. See ../NOTICE.md.

import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Optional

from ldap.filter import escape_filter_chars

from univention_arch_connector.distributions import DomainJoinException
from univention_arch_connector.utils.backup import Backup
from univention_arch_connector.utils.general import execute_as_root

userinfo_logger = logging.getLogger('userinfo')
debug_logger = logging.getLogger('debugging')

SUDOERS_FILE = Path('/etc/sudoers.d/50-univention-arch-connector')
# Before Arch's 50-default.rules: the first addAdminRule() returning
# something wins, so this one lists wheel as well.
POLKIT_RULE = Path('/etc/polkit-1/rules.d/49-univention-arch-connector.rules')
GROUP_MARKER = '# admin-group: '
SUDO_CONF = Path('/etc/sudo.conf')
SUDO_CONF_MARKER = '# univention-arch-connector (--admin-group): look up groups on every sudo call'
SUDO_CONF_SETTING = 'Set group_source dynamic'
# UCS allows more, but these are safe in sudoers (spaces are escaped).
_VALID_NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9._ -]*')


def validate_group_name(group: str) -> None:
    if not _VALID_NAME.fullmatch(group) or group != group.strip():
        raise DomainJoinException(
            "Unsupported admin group name '%s': use letters, digits, spaces, '.', '_' and '-'." % (group,)
        )


def check_requirements() -> None:
    if not shutil.which('visudo'):
        raise DomainJoinException('--admin-group needs sudo. Install it with: pacman -S sudo')


def sudoers_content(group: str) -> str:
    return (
        '# Managed by univention-arch-connector (--admin-group): members of this\n'
        '# UCS group get full sudo rights. Change the members in UCS, not here.\n'
        '%s%s\n'
        '%%%s ALL=(ALL:ALL) ALL\n'
    ) % (GROUP_MARKER, group, group.replace(' ', '\\ '))


def polkit_content(group: str) -> str:
    return (
        '// Managed by univention-arch-connector (--admin-group): members of the\n'
        '// UCS group %s count as administrators, like wheel.\n'
        'polkit.addAdminRule(function(action, subject) {\n'
        '    return [%s, "unix-group:wheel"];\n'
        '});\n'
    ) % (group, json.dumps('unix-group:' + group))


@execute_as_root
def configured_group() -> Optional[str]:
    if not SUDOERS_FILE.exists():
        return None
    for line in SUDOERS_FILE.read_text().splitlines():
        if line.startswith(GROUP_MARKER):
            return line[len(GROUP_MARKER):]
    return None


@execute_as_root
def backup(backup: Backup) -> None:
    backup.backup_file(str(SUDOERS_FILE))
    backup.backup_file(str(POLKIT_RULE))
    backup.backup_file(str(SUDO_CONF))


def _with_dynamic_groups(content: str) -> str:
    """sudo.conf with group_source dynamic, unless group_source is set
    already (by us or the admin).
    """
    if any(line.split()[:2] == ['Set', 'group_source'] for line in content.splitlines()):
        return content
    if content and not content.endswith('\n'):
        content += '\n'
    return content + SUDO_CONF_MARKER + '\n' + SUDO_CONF_SETTING + '\n'


def _without_dynamic_groups(content: str) -> str:
    lines = content.splitlines(keepends=True)
    out = []
    for i, line in enumerate(lines):
        if line.rstrip('\n') == SUDO_CONF_MARKER:
            continue
        if line.rstrip('\n') == SUDO_CONF_SETTING and i > 0 and lines[i - 1].rstrip('\n') == SUDO_CONF_MARKER:
            continue
        out.append(line)
    return ''.join(out)


def _install_sudoers(content: str) -> None:
    """Write via a checked temporary file: a broken sudoers drop-in would
    lock everyone out of sudo.
    """
    SUDOERS_FILE.parent.mkdir(mode=0o750, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(SUDOERS_FILE.parent), prefix='.univention-arch-connector.')
    try:
        with os.fdopen(fd, 'w') as handle:
            handle.write(content)
        os.chmod(tmp, 0o440)
        check = subprocess.run(['visudo', '-c', '-q', '-f', tmp], capture_output=True, text=True)
        if check.returncode != 0:
            raise DomainJoinException('visudo rejected the sudoers rule: %s' % ((check.stderr or check.stdout).strip(),))
        os.replace(tmp, SUDOERS_FILE)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


@execute_as_root
def _setup_impl(group: str) -> None:
    _install_sudoers(sudoers_content(group))
    content = SUDO_CONF.read_text() if SUDO_CONF.exists() else ''
    if _with_dynamic_groups(content) != content:
        SUDO_CONF.write_text(_with_dynamic_groups(content))
    if POLKIT_RULE.parent.is_dir():
        POLKIT_RULE.write_text(polkit_content(group))
        POLKIT_RULE.chmod(0o644)
    else:
        debug_logger.debug('%s missing (polkit not installed); no polkit rule written', POLKIT_RULE.parent)


def group_exists_in_ucs(group: str) -> bool:
    # Imported here: shares imports most join steps.
    from univention_arch_connector.shares import _search
    return bool(_search('(&(objectClass=posixGroup)(cn=%s))' % (escape_filter_chars(group),), ['cn']))


def setup(group: str) -> None:
    validate_group_name(group)
    check_requirements()
    _setup_impl(group)
    userinfo_logger.info('Members of the UCS group %s get administrator (sudo) rights on this system', group)
    try:
        exists = group_exists_in_ucs(group)
    except Exception:
        debug_logger.exception('Could not look up the group %s in UCS', group)
    else:
        if not exists:
            userinfo_logger.warning(
                "There is no group '%s' in UCS yet. Create it in UMC (Users > Groups) and add the users "
                "who should be administrators.", group,
            )


@execute_as_root
def remove() -> None:
    for path in (SUDOERS_FILE, POLKIT_RULE):
        if path.exists():
            path.unlink()
            userinfo_logger.info('Removed %s', path)
    if SUDO_CONF.exists() and SUDO_CONF_MARKER in SUDO_CONF.read_text():
        SUDO_CONF.write_text(_without_dynamic_groups(SUDO_CONF.read_text()))
