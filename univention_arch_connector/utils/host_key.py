#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 univention-arch-connector contributors
# SPDX-License-Identifier: AGPL-3.0-only
#
# New module, with no upstream equivalent (upstream connects with
# StrictHostKeyChecking=no). Scans the domain controller's SSH host keys
# once, has them verified - against a fingerprint given by the admin, or
# by asking interactively - and pins them in a private known_hosts file
# that every later ssh() call is restricted to. See ../../NOTICE.md.

import atexit
import base64
import hashlib
import logging
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Callable, List, Optional

from univention_arch_connector.distributions import DomainJoinException
from univention_arch_connector.utils.general import set_ssh_known_hosts_file

userinfo_logger = logging.getLogger('userinfo')

KEYSCAN_TIMEOUT_SECONDS = 5

KEY_TYPE_NAMES = {
    'ssh-ed25519': 'ED25519',
    'ssh-rsa': 'RSA',
    'ecdsa-sha2-nistp256': 'ECDSA',
    'ecdsa-sha2-nistp384': 'ECDSA',
    'ecdsa-sha2-nistp521': 'ECDSA',
}

VERIFY_HINT = (
    'Compare with the output of `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` '
    'run on the domain controller.'
)


def scan_host_keys(host: str) -> List[str]:
    """Return the host's public keys as known_hosts lines."""
    try:
        output = subprocess.run(
            ['ssh-keyscan', '-T', str(KEYSCAN_TIMEOUT_SECONDS), host],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False,
        ).stdout.decode()
    except OSError as exc:
        raise DomainJoinException('Could not run ssh-keyscan: %s' % (exc,))
    return [line for line in output.splitlines() if line.strip() and not line.startswith('#')]


def fingerprint(known_hosts_line: str) -> str:
    """OpenSSH-style SHA256 fingerprint, as printed by `ssh-keygen -l`."""
    key_blob = base64.b64decode(known_hosts_line.split()[2])
    digest = base64.b64encode(hashlib.sha256(key_blob).digest()).decode().rstrip('=')
    return 'SHA256:%s' % (digest,)


def describe(known_hosts_line: str) -> str:
    key_type = known_hosts_line.split()[1]
    return '%s %s' % (KEY_TYPE_NAMES.get(key_type, key_type), fingerprint(known_hosts_line))


def _normalize(fp: str) -> str:
    fp = fp.strip().rstrip('=')
    return fp if fp.startswith('SHA256:') else 'SHA256:%s' % (fp,)


def pin_host_keys(
    host: str,
    expected_fingerprint: Optional[str],
    confirm: Callable[[str, List[str]], bool],
) -> str:
    """Verify ``host``'s SSH host keys and restrict ssh() to them.

    With ``expected_fingerprint``, one of the scanned keys must match it.
    Otherwise ``confirm(host, descriptions)`` is asked to accept them.
    Returns a fingerprint to verify the host with next time (preferably
    the ED25519 key's, which ssh-keygen -lf shows in the hints above).
    """
    keys = scan_host_keys(host)
    if not keys:
        raise DomainJoinException('Could not read the SSH host keys of %s. Is SSH reachable?' % (host,))

    if expected_fingerprint:
        if not any(fingerprint(key) == _normalize(expected_fingerprint) for key in keys):
            raise DomainJoinException(
                'The SSH host key of %s does not match the given fingerprint %s. It offered: %s. %s' % (
                    host, expected_fingerprint, ', '.join(describe(key) for key in keys), VERIFY_HINT,
                )
            )
    elif not confirm(host, [describe(key) for key in keys]):
        raise DomainJoinException(
            'The SSH host key of %s was not accepted. %s Then pass the fingerprint via --dc-fingerprint.' % (
                host, VERIFY_HINT,
            )
        )

    known_hosts_dir = tempfile.mkdtemp(prefix='univention-arch-connector-')
    atexit.register(shutil.rmtree, known_hosts_dir, ignore_errors=True)
    known_hosts_file = Path(known_hosts_dir) / 'known_hosts'
    known_hosts_file.write_text(''.join('%s\n' % (key,) for key in keys))
    set_ssh_known_hosts_file(str(known_hosts_file))
    userinfo_logger.info('Verified the SSH host key of %s', host)
    preferred = next((key for key in keys if key.split()[1] == 'ssh-ed25519'), keys[0])
    return fingerprint(preferred)
