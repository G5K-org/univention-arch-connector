#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2025 univention-arch-connector contributors
# SPDX-License-Identifier: AGPL-3.0-only
#
# New module, replacing upstream's distribution-specific Joiner
# (univention_domain_join/distributions/ubuntu.py). Unlike upstream, this
# project targets exactly one distribution family (Arch Linux and its
# derivatives), so there is no distribution-dispatch logic like upstream's
# get_joiner_for_this_distribution() - only a check that the running system
# actually is Arch-based, performed by is_arch_based(). The join_domain()
# step ordering mirrors upstream's Joiner.join_domain() with one addition
# (nsswitch_configurator, which Debian doesn't need - see
# nsswitch_configurator.py). See ../../NOTICE.md.

import logging
import subprocess
from pathlib import Path
from typing import Dict, List, Optional

from univention_arch_connector.distributions import AbstractJoiner, DcResolveException, DomainJoinException
from univention_arch_connector.join_steps.dns_configurator import DnsConfigurator
from univention_arch_connector.join_steps.kerberos_configurator import KerberosConfigurator
from univention_arch_connector.join_steps.ldap_configurator import LdapConfigurator
from univention_arch_connector.join_steps.login_manager_configurator import LoginManagerConfigurator
from univention_arch_connector.join_steps.nsswitch_configurator import NsswitchConfigurator
from univention_arch_connector.join_steps.pam_configurator import PamConfigurator
from univention_arch_connector.join_steps.sssd_configurator import SssdConfigurator
from univention_arch_connector.utils.backup import Backup, prune_old_backups
from univention_arch_connector.utils.general import execute_as_root, name_is_resolvable, ssh
from univention_arch_connector.utils.ldap import authenticate_admin, cleanup_authentication, is_samba_dc

userinfo_logger = logging.getLogger('userinfo')
debug_logger = logging.getLogger('debugging')

# UCR variables fetched from the domain controller via SSH before the join
# itself starts. `nameserverN` is read as three separate legacy UCR keys,
# matching how UCS itself still exposes them.
UCR_SCALAR_VARIABLES = [
    'domainname',
    'ldap/master',
    'ldap/base',
    'ldap/server/name',
    'kerberos/realm',
]
UCR_NAMESERVER_VARIABLES = ['nameserver1', 'nameserver2', 'nameserver3']
UCR_REQUIRED_VARIABLES = ['domainname', 'ldap/master', 'ldap/base', 'kerberos/realm']


def is_arch_based() -> bool:
    try:
        info = {}
        for line in Path('/etc/os-release').read_text().splitlines():
            if '=' in line:
                key, _, value = line.partition('=')
                info[key] = value.strip().strip('"')
    except FileNotFoundError:
        return False
    id_like = ('%s %s' % (info.get('ID', ''), info.get('ID_LIKE', ''))).lower()
    return 'arch' in id_like


def check_if_ssh_works_with_given_account(dc_ip: str, admin_username: str, admin_pw: str) -> bool:
    ssh_process = ssh(admin_username, admin_pw, dc_ip, ['true'], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    _, stderr = ssh_process.communicate()
    if ssh_process.returncode:
        debug_logger.debug('SSH check failed: %s', stderr.decode(errors='replace'))
        return False
    return True


def get_ucr_variables_from_dc(dc_ip: str, admin_username: str, admin_pw: str) -> Dict[str, str]:
    """Fetch the handful of UCR (Univention Config Registry) variables
    needed to configure this client, by running `ucr get <key>` on the DC
    once per key over SSH.
    """
    values: Dict[str, str] = {}
    last_error = ''
    for key in UCR_SCALAR_VARIABLES + UCR_NAMESERVER_VARIABLES:
        cmd = ['/usr/sbin/ucr', 'get', key]
        ssh_process = ssh(admin_username, admin_pw, dc_ip, cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = ssh_process.communicate()
        if ssh_process.returncode == 0:
            value = stdout.decode().strip()
            if value:
                values[key] = value
        else:
            last_error = stderr.decode(errors='replace').strip()
            debug_logger.debug('ucr get %s failed: %s', key, last_error)

    missing = [key for key in UCR_REQUIRED_VARIABLES if key not in values]
    if missing:
        raise DomainJoinException(
            'Could not read %s from the domain controller via `ucr get`%s. '
            'Is %s a UCS domain controller?' % (
                ', '.join(missing), ' (%s)' % (last_error,) if last_error else '', dc_ip,
            )
        )
    return values


class ArchJoiner(AbstractJoiner):
    def __init__(
        self,
        ucr_variables: Dict[str, str],
        admin_username: str,
        admin_pw: str,
        dc_ip: str,
        skip_login_manager: bool,
        force_ucs_dns: bool,
    ) -> None:
        super().__init__(ucr_variables, admin_username, admin_pw, dc_ip, skip_login_manager, force_ucs_dns)

        self.domain = ucr_variables['domainname']
        self.nameservers: List[str] = [
            ucr_variables[key] for key in UCR_NAMESERVER_VARIABLES if ucr_variables.get(key)
        ]
        self.ldap_master = ucr_variables['ldap/master']
        self.ldap_base = ucr_variables['ldap/base']
        self.ldap_server_name = ucr_variables.get('ldap/server/name') or self.ldap_master
        self.kerberos_realm = ucr_variables['kerberos/realm']

        self.dns_configurator = DnsConfigurator()
        self.ldap_configurator = LdapConfigurator()
        self.sssd_configurator = SssdConfigurator()
        self.pam_configurator = PamConfigurator()
        self.nsswitch_configurator = NsswitchConfigurator()
        self.login_manager_configurator = LoginManagerConfigurator()
        self.kerberos_configurator = KerberosConfigurator()

        self.admin_dn: Optional[str] = None
        self.is_samba_dc: Optional[bool] = None
        self.machine_password: Optional[str] = None
        self.machine_dn: Optional[str] = None
        self.backup: Optional[Backup] = None

    def check_if_join_is_possible_without_problems(self) -> None:
        self.login_manager_configurator.check_for_conflicts(self.skip_login_manager)

    @execute_as_root
    def create_backup_of_config_files(self) -> None:
        self.backup = Backup.create(joined_before=self.pam_configurator.is_configured())
        if self.force_ucs_dns:
            self.dns_configurator.backup(self.backup)
        self.ldap_configurator.backup(self.backup)
        self.sssd_configurator.backup(self.backup)
        self.pam_configurator.backup(self.backup)
        self.nsswitch_configurator.backup(self.backup)
        self.login_manager_configurator.backup(self.backup, self.skip_login_manager)
        self.kerberos_configurator.backup(self.backup)
        self.backup.write_manifest()
        prune_old_backups()
        userinfo_logger.info('Backup of changed configuration files: %s', self.backup.backup_dir)

    def join_domain(self) -> None:
        try:
            if self.force_ucs_dns:
                self.dns_configurator.configure_dns(self.nameservers, self.domain)
                self.dns_configurator.check_if_dns_works(self.domain)

            if not name_is_resolvable(self.ldap_master) or not name_is_resolvable(self.ldap_server_name):
                raise DcResolveException(
                    "Could not resolve the domain controller's name (%s / %s). "
                    "Rerun with --force-ucs-dns, or fix DNS manually." % (self.ldap_master, self.ldap_server_name)
                )

            userinfo_logger.info('Authenticating as %s on the domain controller', self.admin_username)
            authenticate_admin(self.dc_ip, self.admin_username, self.admin_pw)
            self.admin_dn = self.ldap_configurator.get_admin_dn(self.dc_ip, self.admin_username, self.admin_pw)
            self.is_samba_dc = is_samba_dc(self.admin_username, self.admin_pw, self.dc_ip, self.admin_dn)

            self.machine_password, self.machine_dn = self.ldap_configurator.configure_ldap(
                self.dc_ip, self.admin_username, self.admin_pw, self.admin_dn, self.ldap_master, self.ldap_base,
            )

            self.sssd_configurator.setup_sssd(
                self.domain, self.ldap_master, self.ldap_base, self.machine_dn, self.machine_password,
                self.kerberos_realm, self.ldap_server_name, self.is_samba_dc,
            )
            self.nsswitch_configurator.setup_nsswitch()
            self.pam_configurator.setup_pam()
            if not self.skip_login_manager:
                self.login_manager_configurator.enable_login_with_foreign_usernames()
            self.kerberos_configurator.configure_kerberos(
                self.kerberos_realm, self.ldap_master, self.ldap_server_name, self.is_samba_dc, self.dc_ip,
            )

            userinfo_logger.info('Domain join successful. Please reboot this machine.')
        finally:
            cleanup_authentication(self.dc_ip, self.admin_username, self.admin_pw)
