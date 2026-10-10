#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2025 univention-arch-connector contributors
# SPDX-License-Identifier: AGPL-3.0-only
#
# Lightly adapted from univention-domain-join (upstream module:
# scripts/cli.py). Same argparse surface and overall flow (parse args,
# require root, drop privileges, set up logging, resolve the DC, build a
# Joiner, run the three AbstractJoiner steps). Adds --leave-domain and
# --backup-dir, which upstream doesn't have. See ../NOTICE.md.

import argparse
import getpass
import logging
import os
import sys
from pathlib import Path
from typing import Optional

from univention_arch_connector.distributions import DomainJoinException
from univention_arch_connector.distributions.arch import (
    ArchJoiner,
    check_if_ssh_works_with_given_account,
    get_ucr_variables_from_dc,
    is_arch_based,
)
from univention_arch_connector.leave.leave_domain import leave_domain
from univention_arch_connector.utils.domain import get_master_ip_through_dns, get_ucs_domainname

userinfo_logger = logging.getLogger('userinfo')
debug_logger = logging.getLogger('debugging')

DEFAULT_LOGFILE = '/var/log/univention-arch-connector/domain-join-cli.log'


def parse_args(argv: Optional[list] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description='Join this Arch Linux (or Arch-based) client into a Univention Corporate Server (UCS) domain.'
    )
    parser.add_argument('--username', help='Domain administrator username')
    parser.add_argument(
        '--password',
        help='Domain administrator password. Visible in the process list to other local users; prefer --password-file.',
    )
    parser.add_argument('--password-file', help='File containing the domain administrator password')
    parser.add_argument('--domain', help='UCS domain name (auto-detected via DNS/reverse-DNS if omitted)')
    parser.add_argument('--dc-ip', help='IP address of the UCS domain controller, if --domain auto-detection does not work')
    parser.add_argument('--force-ucs-dns', action='store_true', help="Point this system's DNS configuration at the UCS domain controller")
    parser.add_argument('--skip-login-manager', action='store_true', help="Don't check/configure the login manager for domain logins")
    parser.add_argument('--leave-domain', action='store_true', help='Undo a previous domain join using a backup (see --backup-dir)')
    parser.add_argument('--backup-dir', help='Backup directory to use with --leave-domain (defaults to the most recent one)')
    parser.add_argument('-L', '--logfile', default=DEFAULT_LOGFILE, help='Path to the log file (default: %s)' % (DEFAULT_LOGFILE,))
    return parser.parse_args(argv)


def check_if_run_as_root() -> None:
    if os.geteuid() != 0:
        print('This must be run as root, e.g. via sudo.', file=sys.stderr)
        sys.exit(1)


def drop_privileges() -> None:
    """If invoked via sudo, drop the real/effective UID back to the
    invoking user, keeping the saved UID as root so execute_as_root() can
    briefly restore it for individual privileged operations.
    """
    sudo_uid = os.environ.get('SUDO_UID')
    if sudo_uid is not None:
        ruid = int(sudo_uid)
        os.setresuid(ruid, ruid, 0)


def set_up_logging(logfile: str) -> None:
    Path(logfile).parent.mkdir(parents=True, exist_ok=True)

    file_formatter = logging.Formatter('%(asctime)s %(levelname)s %(name)s: %(message)s')
    file_handler = logging.FileHandler(logfile)
    file_handler.setFormatter(file_formatter)

    stdout_handler = logging.StreamHandler(sys.stdout)
    stdout_handler.setFormatter(logging.Formatter('%(message)s'))

    userinfo_logger.setLevel(logging.INFO)
    userinfo_logger.addHandler(file_handler)
    userinfo_logger.addHandler(stdout_handler)

    debug_logger.setLevel(logging.DEBUG)
    debug_logger.addHandler(file_handler)


def resolve_password(args: argparse.Namespace) -> Optional[str]:
    if args.password:
        return args.password
    if args.password_file:
        try:
            return Path(args.password_file).read_text().rstrip('\n')
        except OSError as exc:
            userinfo_logger.error('Could not read --password-file: %s', exc)
    return None


def resolve_dc_ip(args: argparse.Namespace) -> str:
    if args.dc_ip:
        return args.dc_ip
    domain = args.domain or get_ucs_domainname()
    if not domain:
        userinfo_logger.critical('Could not determine the UCS domain name automatically. Pass --domain or --dc-ip.')
        sys.exit(1)
    dc_ip = get_master_ip_through_dns(domain)
    if not dc_ip:
        userinfo_logger.critical(
            "Could not resolve the domain controller's address for domain '%s' via DNS. Pass --dc-ip explicitly.",
            domain,
        )
        sys.exit(1)
    return dc_ip


def build_joiner(args: argparse.Namespace, dc_ip: str) -> ArchJoiner:
    if not is_arch_based():
        userinfo_logger.critical('This system does not appear to be Arch Linux or an Arch-based distribution.')
        sys.exit(1)

    username = args.username or input('Domain administrator username: ')
    password = resolve_password(args)
    if password is None:
        password = getpass.getpass('Domain administrator password: ')

    if not check_if_ssh_works_with_given_account(dc_ip, username, password):
        userinfo_logger.critical(
            'Could not log in to %s via SSH as %s. Check the credentials and that SSH is reachable.',
            dc_ip, username,
        )
        sys.exit(1)

    userinfo_logger.info('Fetching domain configuration from the domain controller')
    ucr_variables = get_ucr_variables_from_dc(dc_ip, username, password)

    return ArchJoiner(ucr_variables, username, password, dc_ip, args.skip_login_manager, args.force_ucs_dns)


def main(argv: Optional[list] = None) -> None:
    args = parse_args(argv)
    check_if_run_as_root()
    drop_privileges()
    set_up_logging(args.logfile)

    try:
        if args.leave_domain:
            backup_dir = Path(args.backup_dir) if args.backup_dir else None
            leave_domain(backup_dir)
            return

        dc_ip = resolve_dc_ip(args)
        joiner = build_joiner(args, dc_ip)
        joiner.check_if_join_is_possible_without_problems()
        joiner.create_backup_of_config_files()
        joiner.join_domain()
    except SystemExit:
        raise
    except (DomainJoinException, Exception) as exc:
        action = 'Leaving the domain' if args.leave_domain else 'Domain join'
        userinfo_logger.critical('%s failed: %s. See %s for details.', action, exc, args.logfile)
        debug_logger.exception('%s failed', action)
        sys.exit(1)


if __name__ == '__main__':
    main()
