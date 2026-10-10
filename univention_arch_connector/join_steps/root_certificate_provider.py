#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2017-2025 Univention GmbH
# SPDX-FileCopyrightText: 2025 univention-arch-connector contributors
# SPDX-License-Identifier: AGPL-3.0-only
#
# Lightly adapted from univention-domain-join (upstream module:
# univention_domain_join/join_steps/root_certificate_provider.py). The
# unauthenticated download of the UCS root CA over HTTP is unchanged;
# only the final "add to the system trust store" step is swapped from
# Debian's `update-ca-certificates` to Arch's p11-kit-based
# `update-ca-trust extract` (package `ca-certificates-utils`).
# See ../../NOTICE.md.

import logging
import os
import subprocess
from pathlib import Path

from univention_arch_connector.utils.general import execute_as_root

userinfo_logger = logging.getLogger('userinfo')

CA_CERT_PATH = Path('/etc/univention/ssl/ucsCA/CAcert.pem')
TRUST_ANCHOR_PATH = Path('/etc/ca-certificates/trust-source/anchors/UCSdomain.crt')


class RootCertificateProvider:
    def provide_ucs_root_certificate(self, dc_ip: str) -> None:
        if not self.ucs_root_certificate_available_locally():
            self.download_ucs_root_certificate(dc_ip)
            self.add_certificate_to_certificate_store()

    def ucs_root_certificate_available_locally(self) -> bool:
        return CA_CERT_PATH.is_file() and TRUST_ANCHOR_PATH.is_file()

    @execute_as_root
    def download_ucs_root_certificate(self, dc_ip: str) -> None:
        userinfo_logger.info('Downloading the UCS root certificate to %s', CA_CERT_PATH)
        CA_CERT_PATH.parent.mkdir(parents=True, exist_ok=True)
        subprocess.check_output(
            [
                'wget',
                '--no-check-certificate',
                '-O', str(CA_CERT_PATH),
                'http://%s/ucs-root-ca.crt' % (dc_ip,),
            ],
            stderr=subprocess.STDOUT,
        )

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
