#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2017-2025 Univention GmbH
# SPDX-License-Identifier: AGPL-3.0-only
#
# Ported from univention-domain-join (upstream module:
# univention_domain_join/utils/general.py). This module talks only to the
# local process/environment in a distro-agnostic way, so no logic changes
# were needed for the Arch Linux port; only `pipes.quote` (removed in
# Python 3.13) was swapped for its stdlib replacement `shlex.quote`.
#
# Unlike upstream, ssh() no longer disables host key checking: it only
# connects once the DC's host keys have been pinned via
# set_ssh_known_hosts_file() (see utils/host_key.py). See ../../NOTICE.md.

import os
import socket
import subprocess
from functools import wraps
from shlex import quote
from typing import Any, Callable, List, Optional, TypeVar, Union, cast

F = TypeVar('F', bound=Callable[..., Any])

# known_hosts file holding the pinned host keys of the domain controller.
_ssh_known_hosts_file: Optional[str] = None


def set_ssh_known_hosts_file(path: str) -> None:
    global _ssh_known_hosts_file
    _ssh_known_hosts_file = path


def execute_as_root(func: F) -> F:
    """Temporarily restore the real/effective UID to root for the duration
    of ``func``, then drop back to the previous (unprivileged) UIDs.

    This lets the CLI run under ``sudo`` while mostly operating with the
    invoking user's UID, only re-gaining root for the specific filesystem/
    service operations that need it.
    """
    @wraps(func)
    def root_wrapper(*args: Any, **kwargs: Any) -> Any:
        (ruid, euid, suid) = os.getresuid()
        os.setresuid(0, 0, suid)
        try:
            return_value = func(*args, **kwargs)
        finally:
            os.setresuid(ruid, euid, suid)
        return return_value
    return cast(F, root_wrapper)


def short_hostname() -> str:
    """This machine's name without domain, as UCS computer objects are
    named - /etc/hostname may contain the FQDN.
    """
    return socket.gethostname().split('.', 1)[0]


def name_is_resolvable(name: str) -> bool:
    try:
        return bool(socket.getaddrinfo(name, 22, socket.AF_UNSPEC, socket.SOCK_STREAM, socket.IPPROTO_TCP))
    except Exception:
        return False


def ssh(username: str, password: str, hostname: str, command: Union[str, List[str]], **kwargs: Any) -> subprocess.Popen:
    """Run ``command`` on ``hostname`` over SSH as ``username``, authenticating
    with ``password`` via ``sshpass``. Used exclusively to talk to the UCS
    domain controller - never anything local to the Arch client.
    Refuses to run before the DC's host keys have been pinned, so the
    admin password is only ever sent to the verified host.
    """
    if _ssh_known_hosts_file is None:
        raise RuntimeError('SSH host key of the domain controller has not been verified yet')
    cmd = [
        "sshpass",
        "-e",  # Password is passed as env-var "SSHPASS"
        "ssh",
        "-F", "none",
        "-o", "StrictHostKeyChecking=yes",
        "-o", "UserKnownHostsFile=%s" % (_ssh_known_hosts_file,),
        "-l", username,
        hostname,
        command if isinstance(command, str) else " ".join(quote(arg) for arg in command),
    ]
    env = dict(kwargs.pop("env", os.environ), SSHPASS=password)
    proc = subprocess.Popen(cmd, env=env, **kwargs)
    return proc
