#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2017-2025 Univention GmbH
# SPDX-FileCopyrightText: 2025 univention-arch-connector contributors
# SPDX-License-Identifier: AGPL-3.0-only
#
# Ported from univention-domain-join (upstream module:
# univention_domain_join/join_steps/kerberos_configurator.py). The
# krb5.conf content/syntax is identical between Heimdal (upstream) and MIT
# krb5 (Arch's `krb5` package), so no changes were needed there. Two
# adaptations: the time-sync call was extracted to time_sync.py (which
# picks chrony/ntpd instead of the no-longer-packaged `ntpdate`), and
# backup() now delegates to the shared Backup helper instead of a manual
# copyfile. See ../../NOTICE.md.

import logging
from pathlib import Path

from univention_arch_connector.join_steps.time_sync import sync_time
from univention_arch_connector.utils.backup import Backup
from univention_arch_connector.utils.general import execute_as_root

userinfo_logger = logging.getLogger('userinfo')

KRB5_CONF = Path('/etc/krb5.conf')


class ConflictChecker:
    def config_file_exists(self) -> bool:
        if KRB5_CONF.is_file():
            userinfo_logger.warning('Warning: %s already exists.', KRB5_CONF)
            return True
        return False


class KerberosConfigurator(ConflictChecker):
    @execute_as_root
    def backup(self, backup: Backup) -> None:
        backup.backup_file(str(KRB5_CONF))

    def configure_kerberos(self, kerberos_realm: str, ldap_master: str, ldap_server_name: str, is_samba_dc: bool, dc_ip: str) -> None:
        self.write_config_file(kerberos_realm, ldap_master, ldap_server_name, is_samba_dc)
        sync_time(dc_ip)

    @execute_as_root
    def write_config_file(self, kerberos_realm: str, ldap_master: str, ldap_server_name: str, is_samba_dc: bool) -> None:
        userinfo_logger.info('Writing %s', KRB5_CONF)
        if is_samba_dc:
            kpasswd_name = ldap_server_name
        else:
            kpasswd_name = ldap_master
        config = \
            '[libdefaults]\n' \
            '    default_realm = %(kerberos_realm)s\n' \
            '    kdc_timesync = 1\n' \
            '    ccache_type = 4\n' \
            '    forwardable = true\n' \
            '    proxiable = true\n' \
            '    default_tkt_enctypes = arcfour-hmac-md5 des-cbc-md5 des3-hmac-sha1 des-cbc-crc des-cbc-md4 des3-cbc-sha1 aes128-cts-hmac-sha1-96 aes256-cts-hmac-sha1-96\n' \
            '    permitted_enctypes = des3-hmac-sha1 des-cbc-crc des-cbc-md4 des-cbc-md5 des3-cbc-sha1 arcfour-hmac-md5 aes128-cts-hmac-sha1-96 aes256-cts-hmac-sha1-96\n' \
            '    allow_weak_crypto = true\n' \
            '    rdns = false\n' \
            '\n' \
            '[realms]\n' \
            '%(kerberos_realm)s = {\n' \
            '    kdc = %(ldap_server_name)s\n' \
            '    admin_server = %(ldap_server_name)s\n' \
            '    kpasswd_server = %(kpasswd_name)s\n' \
            '}\n' \
            % {
                'kerberos_realm': kerberos_realm,
                'ldap_server_name': ldap_server_name,
                'kpasswd_name': kpasswd_name,
            }
        KRB5_CONF.write_text(config)

    @execute_as_root
    def remove(self) -> None:
        if KRB5_CONF.exists():
            KRB5_CONF.unlink()
