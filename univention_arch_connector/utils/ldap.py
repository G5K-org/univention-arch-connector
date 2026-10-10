#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2017-2025 Univention GmbH
# SPDX-License-Identifier: AGPL-3.0-only
#
# Ported from univention-domain-join (upstream module:
# univention_domain_join/utils/ldap.py). All of this talks exclusively to
# the remote UCS domain controller over SSH and makes no assumptions about
# the client's Linux distribution, so no Arch-specific changes were needed.
# Hardening changes: a failed `kinit` in authenticate_admin() aborts the
# join instead of only being logged. The admin password file on the DC is
# created under umask 077 with an unpredictable name and noclobber -
# upstream creates it world-readable (umask 022) and only chmods it
# afterwards, so other users on the DC could open it in between. Computer
# objects are looked up by the short hostname. See ../../NOTICE.md.

import secrets
import subprocess
from logging import getLogger
from typing import Tuple

from ldap.filter import filter_format

from univention_arch_connector.distributions import DomainJoinException
from univention_arch_connector.utils.general import short_hostname, ssh

_PW_FILE_TOKEN = secrets.token_hex(16)


def PW(admin_username: str) -> str:
    """Path of the admin password file on the DC for this run. The random
    part keeps others on the DC from predicting (and pre-creating) it.
    """
    return '/dev/shm/univention-arch-connector-%s' % (_PW_FILE_TOKEN,)
log = getLogger('debugging')


def authenticate_admin(dc_ip: str, admin_username: str, admin_pw: str) -> None:
    # umask 077: the file must never exist with looser permissions, even
    # briefly. set -C: fail rather than write into a pre-existing file.
    cmd = ['sh', '-e', '-u', '-c', 'umask 077; set -C; cat >"$0"; kinit --password-file="$0"', PW(admin_username)]
    ssh_process = ssh(admin_username, admin_pw, dc_ip, cmd, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    _, stderr = ssh_process.communicate(admin_pw.encode())
    if ssh_process.returncode or stderr:
        log.debug("%r returned %d: %s", cmd, ssh_process.returncode, stderr.decode())
    if ssh_process.returncode:
        raise DomainJoinException(
            'Could not get a Kerberos ticket as %s on the domain controller: %s' % (
                admin_username, stderr.decode(errors='replace').strip() or 'kinit failed',
            )
        )


def cleanup_authentication(dc_ip: str, admin_username: str, admin_pw: str) -> None:
    cmd = ['rm', '-f', PW(admin_username)]
    ssh_process = ssh(admin_username, admin_pw, dc_ip, cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    _, stderr = ssh_process.communicate()
    if ssh_process.returncode or stderr:
        log.debug("%r returned %d: %s", cmd, ssh_process.returncode, stderr.decode())


def is_samba_dc(admin_username: str, admin_pw: str, dc_ip: str, admin_dn: str) -> bool:
    cmd = ['ldapsearch', '-QLLL', filter_format('(&(aRecord=%s)(univentionService=Samba 4))', [dc_ip]), '1.1']
    ssh_process = ssh(admin_username, admin_pw, dc_ip, cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = ssh_process.communicate()
    if ssh_process.returncode or stderr:
        log.debug("%r returned %d: %s", cmd, ssh_process.returncode, stderr.decode())
    return bool(stdout.lstrip())


def get_machines_udm(dc_ip: str, admin_username: str, admin_pw: str, admin_dn: str) -> Tuple[str, str]:
    """Look up this machine's computer object in UCS, trying UDM computer
    types in order. Arch has no dedicated upstream UDM type (unlike
    ``computers/ubuntu``), so only the generic ``computers/linux`` type is
    tried - this is the one deviation from upstream's type list
    ``["computers/ubuntu", "computers/linux", "computers/ucc"]``.
    """
    for udm_type in ['computers/linux']:
        try:
            dn = get_machines_ldap_dn_given_the_udm_type(udm_type, dc_ip, admin_username, admin_pw, admin_dn)
            return (udm_type, dn)
        except LookupError:
            pass
    raise LookupError(dc_ip)


def get_machines_ldap_dn_given_the_udm_type(udm_type: str, dc_ip: str, admin_username: str, admin_pw: str, admin_dn: str) -> str:
    hostname = short_hostname()
    cmd = ['/usr/sbin/udm', udm_type, 'list', '--binddn', admin_dn, '--bindpwdfile', PW(admin_username), '--filter', 'name=%s' % (hostname,)]
    ssh_process = ssh(admin_username, admin_pw, dc_ip, cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert ssh_process.stdout
    for line in ssh_process.stdout:
        key, _, val = line.decode().partition(': ')
        if key == "DN":
            return val.strip()
    _, stderr = ssh_process.communicate()
    if ssh_process.returncode or stderr:
        log.debug("%r returned %d: %s", cmd, ssh_process.returncode, stderr.decode())
    raise LookupError(hostname)
