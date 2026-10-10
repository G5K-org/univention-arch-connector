#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2017-2025 Univention GmbH
# SPDX-License-Identifier: AGPL-3.0-only
#
# Ported verbatim from univention-domain-join (upstream module:
# univention_domain_join/utils/ldap.py). All of this talks exclusively to
# the remote UCS domain controller over SSH and makes no assumptions about
# the client's Linux distribution, so no changes were needed for the Arch
# Linux port. See ../../NOTICE.md.

import subprocess
from logging import getLogger
from socket import gethostname
from typing import Tuple

from ldap.filter import filter_format

from univention_arch_connector.utils.general import ssh

PW = "/dev/shm/{}domain-join".format
log = getLogger('debugging')


def authenticate_admin(dc_ip: str, admin_username: str, admin_pw: str) -> None:
    cmd = ['sh', '-e', '-u', '-c', 'cat >"$0"; chmod 600 "$0"; kinit --password-file="$0"', PW(admin_username)]
    ssh_process = ssh(admin_username, admin_pw, dc_ip, cmd, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    _, stderr = ssh_process.communicate(admin_pw.encode())
    if ssh_process.returncode or stderr:
        log.debug("%r returned %d: %s", cmd, ssh_process.returncode, stderr.decode())


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
    hostname = gethostname()
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
