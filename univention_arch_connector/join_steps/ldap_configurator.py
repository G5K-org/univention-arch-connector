#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2017-2025 Univention GmbH
# SPDX-FileCopyrightText: 2025 univention-arch-connector contributors
# SPDX-License-Identifier: AGPL-3.0-only
#
# Lightly adapted from univention-domain-join (upstream module:
# univention_domain_join/join_steps/ldap_configurator.py). This module
# talks to the remote UCS domain controller over SSH and writes two local
# files, ldap.conf and /etc/machine.secret, so most of it needed no change.
# ldap.conf goes to /etc/openldap/ldap.conf, where Arch's OpenLDAP reads it,
# instead of Debian's /etc/ldap/ldap.conf. Further adaptations: the machine
# is registered in UCS under the generic `computers/linux` UDM type instead of
# `computers/ubuntu` (Arch has no dedicated upstream UDM type - see
# utils/ldap.py), and OS name/version are read from /etc/os-release instead
# of Debian's lsb_release. See ../../NOTICE.md.

import logging
import os
import string
import subprocess
from pathlib import Path
from typing import Tuple

from univention_arch_connector.join_steps.root_certificate_provider import CA_CERT_PATH, RootCertificateProvider
from univention_arch_connector.utils.backup import Backup
from univention_arch_connector.utils.general import execute_as_root, short_hostname, ssh
from univention_arch_connector.utils.ldap import PW, get_machines_udm

userinfo_logger = logging.getLogger('userinfo')
debug_logger = logging.getLogger('debugging')

LDAP_CONF = Path('/etc/openldap/ldap.conf')
MACHINE_SECRET = Path('/etc/machine.secret')


def _os_release_info() -> Tuple[str, str]:
    info = {}
    try:
        for line in Path('/etc/os-release').read_text().splitlines():
            if '=' in line:
                key, _, value = line.partition('=')
                info[key] = value.strip().strip('"')
    except FileNotFoundError:
        pass
    name = info.get('NAME', 'Linux')
    version = info.get('VERSION_ID') or info.get('BUILD_ID') or 'rolling'
    return name, version


class ConflictChecker:
    def config_file_exists(self) -> bool:
        if LDAP_CONF.is_file():
            userinfo_logger.warning('Warning: %s already exists.', LDAP_CONF)
            return True
        return False


class LdapConfigurator(ConflictChecker):
    def __init__(self) -> None:
        self.root_certificate_provider = RootCertificateProvider()

    @execute_as_root
    def backup(self, backup: Backup) -> None:
        backup.backup_file(str(LDAP_CONF))
        backup.backup_file(str(MACHINE_SECRET))
        self.root_certificate_provider.backup(backup)

    def configure_ldap(
        self,
        dc_ip: str,
        admin_username: str,
        admin_pw: str,
        admin_dn: str,
        ldap_master: str,
        ldap_base: str,
    ) -> Tuple[str, str]:
        self.root_certificate_provider.provide_ucs_root_certificate(dc_ip, admin_username, admin_pw)
        machine_password = self.random_password()
        machine_dn = self.modify_old_entry_or_add_machine_to_ldap(dc_ip, admin_username, admin_pw, admin_dn, ldap_base, machine_password)
        self.create_ldap_conf_file(ldap_master, ldap_base)
        self.create_machine_secret_file(machine_password)
        return machine_password, machine_dn

    def modify_old_entry_or_add_machine_to_ldap(
        self, dc_ip: str, admin_username: str, admin_pw: str, admin_dn: str, ldap_base: str, machine_password: str,
    ) -> str:
        try:
            udm_type, dn = get_machines_udm(dc_ip, admin_username, admin_pw, admin_dn)
        except LookupError:
            return self.add_machine_to_ldap(dc_ip, admin_username, admin_pw, admin_dn, ldap_base, machine_password)
        else:
            self.modify_machine_in_ldap(udm_type, dn, dc_ip, admin_username, admin_pw, admin_dn, machine_password)
            return dn

    def get_admin_dn(self, dc_ip: str, admin_username: str, admin_pw: str) -> str:
        cmd = ['ldapwhoami', '-QY', 'GSSAPI']
        ssh_process = ssh(admin_username, admin_pw, dc_ip, cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = ssh_process.communicate()
        if ssh_process.returncode or not stdout.strip():
            raise RuntimeError('Could not determine the admin DN via ldapwhoami: %s' % (stderr.decode(errors='replace'),))
        # Output looks like: "dn:uid=Administrator,cn=users,dc=example,dc=com"
        return stdout.decode().strip().split(':', 1)[-1].strip()

    @execute_as_root
    def add_machine_to_ldap(
        self, dc_ip: str, admin_username: str, admin_pw: str, admin_dn: str, ldap_base: str, machine_password: str,
    ) -> str:
        hostname = short_hostname()
        os_name, os_version = _os_release_info()
        userinfo_logger.info('Creating the computer object "%s" in UCS', hostname)
        position = 'cn=computers,%s' % (ldap_base,)
        cmd = [
            '/usr/sbin/udm', 'computers/linux', 'create',
            '--binddn', admin_dn, '--bindpwdfile', PW(admin_username),
            '--position', position,
            '--set', 'name=%s' % (hostname,),
            '--set', 'password=%s' % (machine_password,),
            '--set', 'operatingSystem=%s' % (os_name,),
            '--set', 'operatingSystemVersion=%s' % (os_version,),
        ]
        ssh_process = ssh(admin_username, admin_pw, dc_ip, cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = ssh_process.communicate()
        if ssh_process.returncode or not stdout.decode().startswith('Object created'):
            raise RuntimeError('Failed to create the computer object in UCS: %s' % (stderr.decode(errors='replace') or stdout.decode(errors='replace'),))
        return 'cn=%s,%s' % (hostname, position)

    @execute_as_root
    def modify_machine_in_ldap(
        self, udm_type: str, dn: str, dc_ip: str, admin_username: str, admin_pw: str, admin_dn: str, machine_password: str,
    ) -> None:
        os_name, os_version = _os_release_info()
        userinfo_logger.info('Updating the existing computer object "%s" in UCS', dn)
        cmd = [
            '/usr/sbin/udm', udm_type, 'modify',
            '--binddn', admin_dn, '--bindpwdfile', PW(admin_username),
            '--dn', dn,
            '--set', 'password=%s' % (machine_password,),
            '--set', 'operatingSystem=%s' % (os_name,),
            '--set', 'operatingSystemVersion=%s' % (os_version,),
        ]
        ssh_process = ssh(admin_username, admin_pw, dc_ip, cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        _, stderr = ssh_process.communicate()
        if ssh_process.returncode:
            raise RuntimeError('Failed to update the computer object in UCS: %s' % (stderr.decode(errors='replace'),))

    @execute_as_root
    def create_ldap_conf_file(self, ldap_master: str, ldap_base: str) -> None:
        userinfo_logger.info('Writing %s', LDAP_CONF)
        LDAP_CONF.parent.mkdir(parents=True, exist_ok=True)
        LDAP_CONF.write_text(
            'TLS_CACERT %s\n'
            'URI ldap://%s:7389/\n'
            'BASE %s\n'
            % (CA_CERT_PATH, ldap_master, ldap_base)
        )

    @execute_as_root
    def create_machine_secret_file(self, machine_password: str) -> None:
        userinfo_logger.info('Writing %s', MACHINE_SECRET)
        MACHINE_SECRET.write_text(machine_password)
        MACHINE_SECRET.chmod(0o600)

    def random_password(self, length: int = 20) -> str:
        alphabet = string.ascii_letters + string.digits + string.punctuation
        return ''.join(alphabet[b % len(alphabet)] for b in os.urandom(length))

    @execute_as_root
    def remove(self) -> None:
        for path in (LDAP_CONF, MACHINE_SECRET):
            if path.exists():
                path.unlink()
