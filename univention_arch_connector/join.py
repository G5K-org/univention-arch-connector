#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 univention-arch-connector contributors
# SPDX-License-Identifier: AGPL-3.0-only
#
# New module: the join flow shared by the CLI (scripts/cli.py) and the GUI
# (scripts/gui.py), which upstream duplicates in both front ends. Adds a
# pre-flight check for required programs, SSH host key verification and an
# automatic rollback of local configuration changes if the join fails
# part-way. See ../NOTICE.md.

import logging
import shutil
from typing import Optional

from univention_arch_connector.distributions import DcResolveException, DomainJoinException
from univention_arch_connector.distributions.arch import (
    ArchJoiner,
    check_if_ssh_works_with_given_account,
    get_ucr_variables_from_dc,
    is_arch_based,
)
from univention_arch_connector.leave.leave_domain import rollback
from univention_arch_connector.utils.domain import get_master_ip_through_dns, get_ucs_domainname

userinfo_logger = logging.getLogger('userinfo')
debug_logger = logging.getLogger('debugging')

# Programs the join runs locally, and the Arch package providing each.
REQUIRED_PROGRAMS = {
    'sshpass': 'sshpass',
    'ssh': 'openssh',
    'ssh-keyscan': 'openssh',
    'sssd': 'sssd',
    'systemctl': 'systemd',
    'update-ca-trust': 'ca-certificates-utils',
}


def check_system() -> None:
    """Fail before anything is changed (or asked for) if this system can't
    be joined.
    """
    if not is_arch_based():
        raise DomainJoinException('This system does not appear to be Arch Linux or an Arch-based distribution.')
    missing = [program for program in REQUIRED_PROGRAMS if not shutil.which(program)]
    if missing:
        packages = sorted({REQUIRED_PROGRAMS[program] for program in missing})
        raise DomainJoinException(
            'Required programs are missing: %s. Install them with: pacman -S %s' % (
                ', '.join(missing), ' '.join(packages),
            )
        )


def resolve_dc_ip(domain: Optional[str], dc_ip: Optional[str]) -> str:
    if dc_ip:
        return dc_ip
    if not domain:
        domain = get_ucs_domainname()
        if not domain:
            raise DcResolveException('Could not determine the UCS domain name automatically. Specify the domain or the DC\'s IP address.')
        userinfo_logger.info('Detected UCS domain %s', domain)
    dc_ip = get_master_ip_through_dns(domain)
    if not dc_ip:
        raise DcResolveException(
            "Could not resolve the domain controller's address for domain '%s' via DNS. "
            "Specify the DC's IP address explicitly." % (domain,)
        )
    return dc_ip


def connect_to_dc(
    dc_ip: str, username: str, password: str, skip_login_manager: bool, force_ucs_dns: bool,
    mount_home: Optional[bool] = None,
) -> ArchJoiner:
    if not check_if_ssh_works_with_given_account(dc_ip, username, password):
        raise DomainJoinException(
            'Could not log in to %s via SSH as %s. Check the credentials and that SSH is reachable.' % (dc_ip, username)
        )
    userinfo_logger.info('Fetching domain configuration from the domain controller')
    ucr_variables = get_ucr_variables_from_dc(dc_ip, username, password)
    return ArchJoiner(ucr_variables, username, password, dc_ip, skip_login_manager, force_ucs_dns, mount_home)


def run_join(joiner: ArchJoiner) -> None:
    """Back up, then join. If the join fails, local configuration changes
    are rolled back before the error is re-raised.
    """
    joiner.check_if_join_is_possible_without_problems()
    joiner.create_backup_of_config_files()
    assert joiner.backup is not None
    backup_dir = joiner.backup.backup_dir
    try:
        joiner.join_domain()
    except BaseException:  # including Ctrl-C, which would leave a half-joined system
        debug_logger.exception('Domain join failed, rolling back')
        try:
            rollback(backup_dir)
            joiner.keep_new_machine_password()
        except Exception:
            debug_logger.exception('Rollback failed')
            userinfo_logger.error(
                'Rolling back failed. Restore manually with --leave-domain --backup-dir %s', backup_dir,
            )
        else:
            userinfo_logger.info(
                'Local configuration restored. A computer object created in UCS during the join was NOT removed.'
            )
        raise
