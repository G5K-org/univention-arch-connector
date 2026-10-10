#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 univention-arch-connector contributors
# SPDX-License-Identifier: AGPL-3.0-only
#
# New module, with no upstream equivalent: which domain users login screens
# list. Login screens (Plasma Login, SDDM, ...) build their user list from
# NSS, where SSSD lists no domain users unless it enumerates all of them.
# Three modes:
#
# - hide:  local users only (the default).
# - known: domain users who logged in on this computer before. SSSD can't
#          filter enumeration by that, so a pam_exec hook stores a systemd
#          user record (/etc/userdb/<name>.user, served by nss-systemd,
#          which Arch's nsswitch.conf already lists before sss) for each
#          domain user at login. Authentication and groups still come from
#          SSSD; the record only makes the user enumerable.
# - all:   SSSD enumerates all active domain users (sssd_configurator.py).
#
# See ../NOTICE.md.

import logging
import pwd
import subprocess
from pathlib import Path
from typing import List

from univention_arch_connector.join_steps.pam_configurator import PamConfigurator
from univention_arch_connector.join_steps.sssd_configurator import SssdConfigurator
from univention_arch_connector.utils.general import execute_as_root

userinfo_logger = logging.getLogger('userinfo')

MODES = ('hide', 'known', 'all')
USERDB_DIR = Path('/etc/userdb')
STATE_FILE = Path('/var/lib/univention-arch-connector/remembered-users')
HOOK = Path('/usr/local/lib/univention-arch-connector/remember-domain-user')
HOME_ROOT = Path('/home')

# Installed as HOOK and run by pam_exec (as root) at every session start.
# Self-contained, since it runs outside this package. It must never make a
# login fail, so it swallows every error.
HOOK_SOURCE = '''#!/usr/bin/python3
# Installed by univention-arch-connector (--login-user-list known): stores a
# systemd user record for each domain user who logs in, so login screens
# list them. Run by pam_exec at session start.
import json
import os
import subprocess
import sys

USERDB_DIR = {userdb_dir!r}
STATE_FILE = {state_file!r}


def remember(user):
    entry = subprocess.run(
        ['getent', '-s', 'sss', 'passwd', user], capture_output=True, text=True, timeout=10,
    ).stdout.strip()
    if not entry:
        return  # not a domain user
    name, _, uid, gid, gecos, home, shell = entry.split(':', 6)
    record = {{
        'userName': name, 'uid': int(uid), 'gid': int(gid), 'realName': gecos or name,
        'homeDirectory': home, 'shell': shell, 'disposition': 'regular',
    }}
    os.makedirs(USERDB_DIR, mode=0o755, exist_ok=True)
    path = os.path.join(USERDB_DIR, name + '.user')
    tmp = path + '.tmp'
    with open(tmp, 'w') as f:
        f.write(json.dumps(record) + '\\n')
    os.chmod(tmp, 0o644)
    os.replace(tmp, path)

    state = {{}}
    if os.path.exists(STATE_FILE):
        for line in open(STATE_FILE).read().split():
            known_name, _, known_uid = line.partition(':')
            state[known_name] = known_uid
    old_uid = state.get(name)
    if old_uid and old_uid != uid:
        try:
            os.unlink(os.path.join(USERDB_DIR, old_uid + '.user'))
        except FileNotFoundError:
            pass
    link = os.path.join(USERDB_DIR, uid + '.user')  # for lookups by UID
    if not (os.path.islink(link) and os.readlink(link) == name + '.user'):
        if os.path.lexists(link):
            os.unlink(link)
        os.symlink(name + '.user', link)
    state[name] = uid
    os.makedirs(os.path.dirname(STATE_FILE), mode=0o755, exist_ok=True)
    with open(STATE_FILE + '.tmp', 'w') as f:
        f.write(''.join('%s:%s\\n' % item for item in sorted(state.items())))
    os.replace(STATE_FILE + '.tmp', STATE_FILE)


if __name__ == '__main__':
    try:
        if os.environ.get('PAM_TYPE', 'open_session') == 'open_session':
            for user in sys.argv[1:] or [os.environ.get('PAM_USER', '')]:
                if user:
                    remember(user)
    except Exception:
        pass
    sys.exit(0)
'''


def hook_source() -> str:
    return HOOK_SOURCE.format(userdb_dir=str(USERDB_DIR), state_file=str(STATE_FILE))


def remembered_users() -> List[str]:
    if not STATE_FILE.exists():
        return []
    return [line.partition(':')[0] for line in STATE_FILE.read_text().split()]


def _forget_all_impl() -> None:
    if STATE_FILE.exists():
        for line in STATE_FILE.read_text().split():
            name, _, uid = line.partition(':')
            for path in (USERDB_DIR / ('%s.user' % name), USERDB_DIR / ('%s.user' % uid)):
                if path.is_symlink() or path.exists():
                    path.unlink()
        STATE_FILE.unlink()
    if USERDB_DIR.is_dir() and not any(USERDB_DIR.iterdir()):
        USERDB_DIR.rmdir()


def _domain_users_with_a_home() -> List[str]:
    """Domain users who have logged in here before: their home directory
    was created at first login (pam_mkhomedir).
    """
    users = []
    for home in sorted(HOME_ROOT.iterdir()) if HOME_ROOT.is_dir() else []:
        try:
            owner = pwd.getpwuid(home.stat().st_uid).pw_name
        except (KeyError, OSError):
            continue
        result = subprocess.run(['getent', '-s', 'sss', 'passwd', owner], capture_output=True, text=True)
        if result.stdout.strip():
            users.append(owner)
    return users


@execute_as_root
def _enable_known() -> None:
    HOOK.parent.mkdir(parents=True, exist_ok=True)
    HOOK.write_text(hook_source())
    HOOK.chmod(0o755)
    PamConfigurator().enable_remember_hook(str(HOOK))
    already = _domain_users_with_a_home()
    if already:
        subprocess.run([str(HOOK), *already], check=False)
        userinfo_logger.info('Listing domain users who logged in here before: %s', ', '.join(remembered_users()))


@execute_as_root
def _disable_known() -> None:
    PamConfigurator().disable_remember_hook()
    _forget_all_impl()
    if HOOK.exists():
        HOOK.unlink()
    for directory in (HOOK.parent, STATE_FILE.parent):
        if directory.is_dir() and not any(directory.iterdir()):
            directory.rmdir()


@execute_as_root
def current_mode() -> str:
    if PamConfigurator().remember_hook_enabled():
        return 'known'
    return 'all' if SssdConfigurator().domain_users_listed() else 'hide'


def set_mode(mode: str) -> None:
    if mode not in MODES:
        raise ValueError(mode)
    # 'known' and 'all' would list users twice (userdb and SSSD), so only
    # one of them is active at a time.
    if mode != 'known':
        _disable_known()
    if mode != 'all' and SssdConfigurator().domain_users_listed():
        SssdConfigurator().set_domain_users_listed(False)
    if mode == 'known':
        _enable_known()
        userinfo_logger.info('The login screen lists domain users after their first login on this computer')
    elif mode == 'all':
        SssdConfigurator().set_domain_users_listed(True)
    else:
        userinfo_logger.info('The login screen lists local users only')


def remove() -> None:
    """For --leave-domain."""
    _disable_known()
