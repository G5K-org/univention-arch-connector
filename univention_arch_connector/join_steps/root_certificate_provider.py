#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2017-2025 Univention GmbH
# SPDX-FileCopyrightText: 2025 univention-arch-connector contributors
# SPDX-License-Identifier: AGPL-3.0-only
#
# Adapted from univention-domain-join (upstream module:
# univention_domain_join/join_steps/root_certificate_provider.py). Two
# changes: upstream downloads the UCS root CA over unauthenticated plain
# HTTP before trusting it system-wide; this reads it over the already
# authenticated, host-key-verified SSH connection to the DC instead. And
# the "add to the system trust store" step is swapped from Debian's
# `update-ca-certificates` to Arch's p11-kit-based `update-ca-trust
# extract` (package `ca-certificates-utils`). Both files are recorded in
# the backup, so --leave-domain and a failed join's rollback remove the
# CA again. See ../../NOTICE.md.

import logging
import os
import ssl
import subprocess
from pathlib import Path

from univention_arch_connector.distributions import DomainJoinException
from univention_arch_connector.utils.backup import Backup
from univention_arch_connector.utils.general import execute_as_root, ssh

userinfo_logger = logging.getLogger('userinfo')

CA_CERT_PATH = Path('/etc/univention/ssl/ucsCA/CAcert.pem')
# Same path on the UCS domain controller.
DC_CA_CERT_PATH = '/etc/univention/ssl/ucsCA/CAcert.pem'
TRUST_ANCHOR_PATH = Path('/etc/ca-certificates/trust-source/anchors/UCSdomain.crt')


class RootCertificateProvider:
    @execute_as_root
    def backup(self, backup: Backup) -> None:
        backup.backup_file(str(CA_CERT_PATH))
        backup.backup_file(str(TRUST_ANCHOR_PATH))

    def provide_ucs_root_certificate(self, dc_ip: str, admin_username: str, admin_pw: str) -> None:
        if not self.ucs_root_certificate_available_locally():
            self.download_ucs_root_certificate(dc_ip, admin_username, admin_pw)
            self.add_certificate_to_certificate_store()

    def ucs_root_certificate_available_locally(self) -> bool:
        return CA_CERT_PATH.is_file() and TRUST_ANCHOR_PATH.is_file()

    def download_ucs_root_certificate(self, dc_ip: str, admin_username: str, admin_pw: str) -> None:
        userinfo_logger.info('Downloading the UCS root certificate to %s', CA_CERT_PATH)
        ssh_process = ssh(admin_username, admin_pw, dc_ip, ['cat', DC_CA_CERT_PATH], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = ssh_process.communicate()
        certificate = stdout.decode(errors='replace')
        try:
            if ssh_process.returncode:
                raise ValueError(stderr.decode(errors='replace').strip())
            ssl.PEM_cert_to_DER_cert(certificate)
        except ValueError as exc:
            raise DomainJoinException('Could not read the UCS root certificate %s from the domain controller: %s' % (DC_CA_CERT_PATH, exc))
        self._write_ca_cert(certificate)

    @execute_as_root
    def _write_ca_cert(self, certificate: str) -> None:
        CA_CERT_PATH.parent.mkdir(parents=True, exist_ok=True)
        CA_CERT_PATH.write_text(certificate)
        CA_CERT_PATH.chmod(0o644)

    @execute_as_root
    def add_certificate_to_certificate_store(self) -> None:
        userinfo_logger.info('Adding the UCS root certificate to the system trust store')
        TRUST_ANCHOR_PATH.parent.mkdir(parents=True, exist_ok=True)
        if TRUST_ANCHOR_PATH.exists() or TRUST_ANCHOR_PATH.is_symlink():
            TRUST_ANCHOR_PATH.unlink()
        os.symlink(CA_CERT_PATH, TRUST_ANCHOR_PATH)
        subprocess.check_output(['update-ca-trust', 'extract'], stderr=subprocess.STDOUT)

    @execute_as_root
    def remove(self) -> None:
        if TRUST_ANCHOR_PATH.exists() or TRUST_ANCHOR_PATH.is_symlink():
            TRUST_ANCHOR_PATH.unlink()
            subprocess.check_output(['update-ca-trust', 'extract'], stderr=subprocess.STDOUT)
