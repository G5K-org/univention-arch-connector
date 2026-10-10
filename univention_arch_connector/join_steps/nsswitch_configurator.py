#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2025 univention-arch-connector contributors
# SPDX-License-Identifier: AGPL-3.0-only
#
# New module, with no upstream equivalent: on Debian/Ubuntu, installing
# `libnss-sss` automatically adds `sss` to the relevant lines of
# /etc/nsswitch.conf via its postinst script. Arch's `sssd` package ships
# the same NSS module but has no such postinst hook, so this project has to
# perform that edit itself. See ../../NOTICE.md.

import logging
import re
from pathlib import Path
from typing import List

from univention_arch_connector.utils.backup import Backup
from univention_arch_connector.utils.general import execute_as_root

userinfo_logger = logging.getLogger('userinfo')

NSSWITCH_CONF = Path('/etc/nsswitch.conf')
DEFAULT_DATABASES = ['passwd', 'group', 'shadow']

_LINE_RE = re.compile(r'^(\s*)([a-z_]+):(\s*)(.*)$')


def _databases(enable_sudo: bool) -> List[str]:
    databases = list(DEFAULT_DATABASES)
    if enable_sudo:
        databases.append('sudoers')
    return databases


def _add_sss_to_line(line: str, databases: List[str]) -> str:
    stripped = line.rstrip('\n')
    match = _LINE_RE.match(stripped)
    if not match:
        return line
    indent, db, sep, rest = match.groups()
    if db not in databases:
        return line
    if re.search(r'\bsss\b', rest):
        return line
    rest_stripped = rest.rstrip()
    new_rest = (rest_stripped + ' sss') if rest_stripped else 'sss'
    newline_suffix = '\n' if line.endswith('\n') else ''
    return '%s%s:%s%s%s' % (indent, db, sep, new_rest, newline_suffix)


def _remove_sss_from_line(line: str, databases: List[str]) -> str:
    stripped = line.rstrip('\n')
    match = _LINE_RE.match(stripped)
    if not match:
        return line
    indent, db, sep, rest = match.groups()
    if db not in databases:
        return line
    new_rest = re.sub(r'\s*\bsss\b', '', rest).strip()
    newline_suffix = '\n' if line.endswith('\n') else ''
    return '%s%s:%s%s%s' % (indent, db, sep, new_rest, newline_suffix)


def _setup_nsswitch_impl(enable_sudo: bool = False) -> None:
    """Undecorated implementation, called by the (root-requiring) class
    method below and directly by unit tests (which can't satisfy
    execute_as_root's privilege dance as an unprivileged test process).
    """
    databases = _databases(enable_sudo)
    lines = NSSWITCH_CONF.read_text().splitlines(keepends=True)
    new_lines = [_add_sss_to_line(line, databases) for line in lines]
    if new_lines != lines:
        userinfo_logger.info('Adding sss to %s for: %s', NSSWITCH_CONF, ', '.join(databases))
        NSSWITCH_CONF.write_text(''.join(new_lines))


def _remove_nsswitch_impl(enable_sudo: bool = False) -> None:
    if not NSSWITCH_CONF.exists():
        return
    databases = _databases(enable_sudo)
    lines = NSSWITCH_CONF.read_text().splitlines(keepends=True)
    new_lines = [_remove_sss_from_line(line, databases) for line in lines]
    if new_lines != lines:
        userinfo_logger.info('Removing sss from %s for: %s', NSSWITCH_CONF, ', '.join(databases))
        NSSWITCH_CONF.write_text(''.join(new_lines))


class NsswitchConfigurator:
    @execute_as_root
    def backup(self, backup: Backup) -> None:
        backup.backup_file(str(NSSWITCH_CONF))

    @execute_as_root
    def setup_nsswitch(self, enable_sudo: bool = False) -> None:
        _setup_nsswitch_impl(enable_sudo)

    @execute_as_root
    def remove(self, enable_sudo: bool = False) -> None:
        _remove_nsswitch_impl(enable_sudo)
