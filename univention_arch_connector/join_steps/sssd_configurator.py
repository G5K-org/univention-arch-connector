#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2017-2025 Univention GmbH
# SPDX-FileCopyrightText: 2025 univention-arch-connector contributors
# SPDX-License-Identifier: AGPL-3.0-only
#
# Lightly adapted from univention-domain-join (upstream module:
# univention_domain_join/join_steps/sssd_configurator.py). The sssd.conf
# content itself (LDAP id_provider + Kerberos auth_provider, port 7389,
# machine-account bind, kpasswd-server selection) is unchanged - Arch's
# `sssd` package is the same upstream SSSD project. One functional
# change is dropping the Debian-only `pam-auth-update` call: pam_sss and
# mkhomedir activation on Arch happen exclusively via pam_configurator.py, and
# `sss` is wired into NSS via nsswitch_configurator.py instead of relying
# on a Debian postinst script. Also sets ldap_id_use_start_tls explicitly:
# SSSD (2.x, tested) already uses StartTLS for the machine account's
# password bind and fails rather than falling back to plain LDAP, but this
# keeps encryption mandatory independent of SSSD's defaults. And stores
# Kerberos tickets at MIT's default location /tmp/krb5cc_<uid> instead of
# SSSD's randomized name: mounting shares at login (shares.py) runs as root,
# and cifs.upcall then only looks at the default location.
#
# Optionally (set_domain_users_listed) SSSD lists domain users, so login
# screens - which build their user list from NSS - show them. Like
# upstream's enumerate = true, but restricted to active, visible person
# accounts: UCS also has machine accounts (uid ending in $), hidden
# service accounts and disabled ones (krbtgt, Guest) in the UID range
# login screens show. See ../../NOTICE.md.

import logging
import subprocess
from pathlib import Path

from univention_arch_connector.join_steps.root_certificate_provider import CA_CERT_PATH
from univention_arch_connector.utils.backup import Backup
from univention_arch_connector.utils.general import execute_as_root

userinfo_logger = logging.getLogger('userinfo')

SSSD_CONF = Path('/etc/sssd/sssd.conf')
CCNAME_TEMPLATE = 'FILE:/tmp/krb5cc_%U'
# Accounts shown on login screens when domain users are listed.
LISTED_USERS_FILTER = '(&(objectClass=inetOrgPerson)(!(univentionObjectFlag=hidden))(!(shadowExpire=1)))'


@execute_as_root
def is_joined() -> bool:
    # As root: /etc/sssd isn't readable for others, so as the sudo caller
    # the file would always seem to be missing.
    return SSSD_CONF.exists()


def _key(line: str) -> str:
    return line.split('=', 1)[0].strip()


class ConflictChecker:
    def config_file_exists(self) -> bool:
        if SSSD_CONF.is_file():
            userinfo_logger.warning('Warning: %s already exists.', SSSD_CONF)
            return True
        return False


class SssdConfigurator(ConflictChecker):
    @execute_as_root
    def backup(self, backup: Backup) -> None:
        backup.backup_file(str(SSSD_CONF))

    def setup_sssd(
        self,
        domain: str,
        ldap_master: str,
        ldap_base: str,
        machine_dn: str,
        machine_password: str,
        kerberos_realm: str,
        ldap_server_name: str,
        is_samba_dc: bool,
    ) -> None:
        # A re-join keeps the login screen setting.
        listed = self.domain_users_listed()
        self.write_sssd_conf(domain, ldap_master, ldap_base, machine_dn, machine_password, kerberos_realm, ldap_server_name, is_samba_dc)
        if listed:
            self.set_domain_users_listed(True, restart=False)
        self.restart_sssd()

    @execute_as_root
    def write_sssd_conf(
        self,
        domain: str,
        ldap_master: str,
        ldap_base: str,
        machine_dn: str,
        machine_password: str,
        kerberos_realm: str,
        ldap_server_name: str,
        is_samba_dc: bool,
    ) -> None:
        userinfo_logger.info('Writing %s', SSSD_CONF)
        kpasswd_name = ldap_server_name if is_samba_dc else ldap_master
        config = (
            '[sssd]\n'
            'services = nss, pam\n'
            'config_file_version = 2\n'
            'domains = %(domain)s\n'
            '\n'
            '[domain/%(domain)s]\n'
            'id_provider = ldap\n'
            'auth_provider = krb5\n'
            'chpass_provider = krb5\n'
            'ldap_uri = ldap://%(ldap_master)s:7389/\n'
            'ldap_id_use_start_tls = true\n'
            'ldap_search_base = %(ldap_base)s\n'
            'ldap_tls_reqcert = demand\n'
            'ldap_tls_cacert = %(ca_cert)s\n'
            'ldap_default_bind_dn = %(machine_dn)s\n'
            'ldap_default_authtok_type = password\n'
            'ldap_default_authtok = %(machine_password)s\n'
            'krb5_server = %(ldap_server_name)s\n'
            'krb5_kpasswd = %(kpasswd_name)s\n'
            'krb5_realm = %(kerberos_realm)s\n'
            'krb5_ccname_template = %(ccname_template)s\n'
            'cache_credentials = true\n'
            # How soon group changes in UCS apply here, e.g. --admin-group
            # (default: 90 minutes). Offline, expired entries are still used.
            'entry_cache_timeout = 600\n'
            'enumerate = false\n'
            '\n'
            '[nss]\n'
            '\n'
            '[pam]\n'
            % {
                'domain': domain,
                'ldap_master': ldap_master,
                'ldap_base': ldap_base,
                'ca_cert': CA_CERT_PATH,
                'machine_dn': machine_dn,
                'machine_password': machine_password,
                'ldap_server_name': ldap_server_name,
                'kpasswd_name': kpasswd_name,
                'kerberos_realm': kerberos_realm,
                'ccname_template': CCNAME_TEMPLATE,
            }
        )
        SSSD_CONF.parent.mkdir(parents=True, exist_ok=True)
        SSSD_CONF.write_text(config)
        SSSD_CONF.chmod(0o600)

    @execute_as_root
    def domain_users_listed(self) -> bool:
        if not SSSD_CONF.exists():
            return False
        return any(_key(line) == 'enumerate' and line.split('=', 1)[1].strip() == 'true'
                   for line in SSSD_CONF.read_text().splitlines())

    @execute_as_root
    def set_domain_users_listed(self, listed: bool, restart: bool = True) -> None:
        """List (or stop listing) domain users via NSS, e.g. on login
        screens. Changes only the enumerate and ldap_user_search_base lines.
        """
        lines = [line for line in SSSD_CONF.read_text().splitlines(keepends=True) if _key(line) != 'ldap_user_search_base']
        search_base = next((line.split('=', 1)[1].strip() for line in lines if _key(line) == 'ldap_search_base'), None)
        if search_base is None:
            raise RuntimeError('No ldap_search_base line in %s; was this system joined with this tool?' % (SSSD_CONF,))
        out = []
        for line in lines:
            if _key(line) == 'enumerate':
                line = 'enumerate = %s\n' % ('true' if listed else 'false',)
            out.append(line)
            if listed and _key(line) == 'ldap_search_base':
                out.append('ldap_user_search_base = %s?subtree?%s\n' % (search_base, LISTED_USERS_FILTER))
        SSSD_CONF.write_text(''.join(out))
        if not restart:
            return
        userinfo_logger.info('%s domain users on the login screen', 'Showing' if listed else 'Not showing')
        if listed:
            # Accounts cached before (e.g. krbtgt) would still be listed even
            # though the filter now excludes them. Clearing the cache also
            # drops cached passwords: offline logins work again after each
            # user's next login with the DC reachable.
            userinfo_logger.info('Clearing the SSSD cache; users need one login with the DC reachable before logging in offline')
            subprocess.check_output(
                ['sssctl', 'cache-remove', '--override', '--stop', '--start', '--restore'],
                stdin=subprocess.DEVNULL, stderr=subprocess.STDOUT,
            )
        else:
            subprocess.check_output(['systemctl', 'restart', 'sssd'], stderr=subprocess.STDOUT)

    @execute_as_root
    def update_machine_password(self, machine_password: str) -> None:
        """Replace the machine account password in sssd.conf."""
        lines = SSSD_CONF.read_text().splitlines(keepends=True)
        SSSD_CONF.write_text(''.join(
            'ldap_default_authtok = %s\n' % (machine_password,) if _key(line) == 'ldap_default_authtok' else line
            for line in lines
        ))
        subprocess.check_output(['systemctl', 'restart', 'sssd'], stderr=subprocess.STDOUT)

    @execute_as_root
    def ensure_default_ccache_location(self) -> None:
        """Add krb5_ccname_template to an sssd.conf written by an older
        version of this tool (needed for mounting shares).
        """
        lines = SSSD_CONF.read_text().splitlines(keepends=True)
        if any(line.split('=', 1)[0].strip() == 'krb5_ccname_template' for line in lines):
            return
        for i, line in enumerate(lines):
            if line.split('=', 1)[0].strip() == 'krb5_realm':
                lines.insert(i + 1, 'krb5_ccname_template = %s\n' % (CCNAME_TEMPLATE,))
                break
        else:
            raise RuntimeError('No krb5_realm line in %s; was this system joined with this tool?' % (SSSD_CONF,))
        userinfo_logger.info('Storing Kerberos tickets at /tmp/krb5cc_<uid> (%s)', SSSD_CONF)
        SSSD_CONF.write_text(''.join(lines))
        subprocess.check_output(['systemctl', 'restart', 'sssd'], stderr=subprocess.STDOUT)

    @execute_as_root
    def restart_sssd(self) -> None:
        userinfo_logger.info('Restarting sssd')
        subprocess.check_output(['systemctl', 'enable', '--now', 'sssd'], stderr=subprocess.STDOUT)
        subprocess.check_output(['systemctl', 'restart', 'sssd'], stderr=subprocess.STDOUT)

    @execute_as_root
    def remove(self) -> None:
        subprocess.call(['systemctl', 'disable', '--now', 'sssd'])
        if SSSD_CONF.exists():
            SSSD_CONF.unlink()
