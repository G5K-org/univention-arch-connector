# SPDX-FileCopyrightText: 2026 univention-arch-connector contributors
# SPDX-License-Identifier: AGPL-3.0-only

import json
import os
import subprocess
import sys
from pathlib import Path

from univention_arch_connector import login_users


def _run_hook(tmp_path: Path, passwd_lines, users, env=None):
    """Run the real hook script, with a fake `getent -s sss passwd` and
    the userdb/state paths pointing into tmp_path.
    """
    bin_dir = tmp_path / 'bin'
    bin_dir.mkdir(exist_ok=True)
    getent = bin_dir / 'getent'
    getent.write_text('#!/bin/sh\n' + ''.join(
        '[ "$4" = %s ] && echo %s && exit 0\n' % (line.split(':')[0], "'%s'" % line) for line in passwd_lines
    ) + 'exit 2\n')
    getent.chmod(0o755)
    hook = tmp_path / 'hook'
    source = login_users.HOOK_SOURCE.format(userdb_dir=str(tmp_path / 'userdb'), state_file=str(tmp_path / 'state' / 'users'))
    hook.write_text(source)
    environment = dict(os.environ, PATH='%s:%s' % (bin_dir, os.environ['PATH']), **(env or {}))
    return subprocess.run([sys.executable, str(hook), *users], env=environment, capture_output=True, text=True)


ALICE = 'alice:*:2010:5001:Alice Example:/home/alice:/bin/bash'


def test_hook_stores_a_userdb_record_for_domain_users(tmp_path):
    result = _run_hook(tmp_path, [ALICE], ['alice'])
    assert result.returncode == 0, result.stderr
    record = json.loads((tmp_path / 'userdb' / 'alice.user').read_text())
    assert record == {
        'userName': 'alice', 'uid': 2010, 'gid': 5001, 'realName': 'Alice Example',
        'homeDirectory': '/home/alice', 'shell': '/bin/bash', 'disposition': 'regular',
    }
    assert os.readlink(tmp_path / 'userdb' / '2010.user') == 'alice.user'
    assert (tmp_path / 'state' / 'users').read_text() == 'alice:2010\n'


def test_hook_runs_from_pam_environment_and_ignores_local_users(tmp_path):
    result = _run_hook(tmp_path, [ALICE], [], env={'PAM_TYPE': 'open_session', 'PAM_USER': 'gsk'})
    assert result.returncode == 0 and not (tmp_path / 'userdb').exists()
    _run_hook(tmp_path, [ALICE], [], env={'PAM_TYPE': 'close_session', 'PAM_USER': 'alice'})
    assert not (tmp_path / 'userdb').exists()
    _run_hook(tmp_path, [ALICE], [], env={'PAM_TYPE': 'open_session', 'PAM_USER': 'alice'})
    assert (tmp_path / 'userdb' / 'alice.user').exists()


def test_hook_follows_a_changed_uid(tmp_path):
    _run_hook(tmp_path, [ALICE], ['alice'])
    _run_hook(tmp_path, [ALICE.replace('2010', '2099')], ['alice'])
    assert not (tmp_path / 'userdb' / '2010.user').is_symlink()
    assert os.readlink(tmp_path / 'userdb' / '2099.user') == 'alice.user'


def test_hook_never_fails_a_login(tmp_path):
    (tmp_path / 'userdb').write_text('not a directory')
    result = _run_hook(tmp_path, [ALICE], ['alice'])
    assert result.returncode == 0


def test_forget_all_removes_only_remembered_records(monkeypatch, tmp_path):
    _run_hook(tmp_path, [ALICE], ['alice'])
    other = tmp_path / 'userdb' / 'someone-else.user'
    other.write_text('{}')
    monkeypatch.setattr(login_users, 'USERDB_DIR', tmp_path / 'userdb')
    monkeypatch.setattr(login_users, 'STATE_FILE', tmp_path / 'state' / 'users')

    login_users._forget_all_impl()

    assert sorted(p.name for p in (tmp_path / 'userdb').iterdir()) == ['someone-else.user']
    assert not (tmp_path / 'state' / 'users').exists()
