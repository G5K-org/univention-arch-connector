#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2025 univention-arch-connector contributors
# SPDX-License-Identifier: AGPL-3.0-only
#
# Lightly adapted from univention-domain-join (upstream module:
# scripts/cli.py). Same argparse surface and overall flow (parse args,
# require root, drop privileges, set up logging, resolve the DC, build a
# Joiner, run the three AbstractJoiner steps), now via the shared
# univention_arch_connector.join module. Adds --leave-domain, --backup-dir
# and --dc-fingerprint, which upstream doesn't have. See ../NOTICE.md.

import argparse
import getpass
import logging
import os
import sys
from pathlib import Path
from typing import List, Optional

from univention_arch_connector.join import check_system, connect_to_dc, resolve_dc_ip, run_join
from univention_arch_connector import shares
from univention_arch_connector import login_users
from univention_arch_connector.join_steps.sssd_configurator import is_joined
from univention_arch_connector.leave.leave_domain import leave_domain
from univention_arch_connector.utils.general import execute_as_root
from univention_arch_connector.utils.host_key import pin_host_keys

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
    parser.add_argument(
        '--dc-fingerprint',
        help="SHA256 fingerprint of the domain controller's SSH host key (from `ssh-keygen -lf "
             "/etc/ssh/ssh_host_ed25519_key.pub` on the DC). Required when not running interactively.",
    )
    parser.add_argument('--force-ucs-dns', action='store_true', help="Point this system's DNS configuration at the UCS domain controller")
    parser.add_argument('--skip-login-manager', action='store_true', help="Don't check/configure the login manager for domain logins")
    parser.add_argument('--leave-domain', action='store_true', help='Undo a previous domain join using a backup (see --backup-dir)')
    parser.add_argument('--list-shares', action='store_true', help='List the file shares defined in UCS (after joining)')
    parser.add_argument(
        '--setup-shares', nargs='*', metavar='SHARE',
        help='Mount these UCS shares at login under %s/<name>, plus each user\'s home share if set in UCS. '
             'Without names, choose interactively.' % (shares.MOUNT_DIR,),
    )
    parser.add_argument('--remove-shares', action='store_true', help='Stop mounting shares at login')
    parser.add_argument(
        '--login-user-list', choices=login_users.MODES,
        help="Which domain users the login screen lists (after joining): 'known' - those who logged in on "
             "this computer before, 'all' - all active ones (for small domains), 'hide' - none.",
    )
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


@execute_as_root
def read_password_file(path: str) -> str:
    # As root: under sudo the caller is root anyway, and the file is often root-only.
    return Path(path).read_text().rstrip('\n')


def resolve_password(args: argparse.Namespace) -> Optional[str]:
    if args.password:
        return args.password
    if args.password_file:
        try:
            return read_password_file(args.password_file)
        except OSError as exc:
            raise RuntimeError('Could not read --password-file: %s' % (exc,))
    return None


def confirm_host_key(dc_ip: str, fingerprints: List[str]) -> bool:
    if not sys.stdin.isatty():
        userinfo_logger.error(
            'Cannot ask to confirm the SSH host key of %s (%s) without a terminal.', dc_ip, ', '.join(fingerprints),
        )
        return False
    print('The SSH host key of the domain controller %s is:' % (dc_ip,))
    for fingerprint in fingerprints:
        print('  %s' % (fingerprint,))
    return input('Is this the right domain controller (yes/no)? ').strip().lower() in ('y', 'yes')


def choose_shares(available: List[str], configured: List[str]) -> List[str]:
    if not sys.stdin.isatty():
        raise RuntimeError('Pass the share names to --setup-shares when not running interactively.')
    print('Shares in UCS (* = currently set up):')
    for number, name in enumerate(available, 1):
        print('  %2d) %s%s' % (number, name, ' *' if name in configured else ''))
    answer = input("Shares to mount (numbers separated by commas, 'all', or empty for none): ").strip().lower()
    if answer == 'all':
        return list(available)
    chosen = []
    for part in filter(None, (part.strip() for part in answer.split(','))):
        if not part.isdigit() or not 1 <= int(part) <= len(available):
            raise RuntimeError('Invalid choice: %s' % (part,))
        chosen.append(available[int(part) - 1])
    return chosen


def run_shares_command(args: argparse.Namespace) -> None:
    if args.remove_shares:
        shares.remove_shares()
        return
    available = shares.list_shares()
    configured = shares.configured_share_names()
    if args.list_shares:
        for share in available:
            print('%s  //%s/%s%s' % (share.name, share.host, share.name, '  (set up)' if share.name in configured else ''))
        homes = shares.list_home_shares()
        print('%d user(s) have a home share in UCS.' % (len(homes),))
        return
    names = args.setup_shares or choose_shares([share.name for share in available], configured)
    shares.setup_shares(names)


def main(argv: Optional[list] = None) -> None:
    args = parse_args(argv)
    check_if_run_as_root()
    # Open the log file while still root: after dropping privileges under
    # sudo, /var/log is no longer writable.
    set_up_logging(args.logfile)
    drop_privileges()

    try:
        if args.leave_domain:
            backup_dir = Path(args.backup_dir) if args.backup_dir else None
            leave_domain(backup_dir)
            return
        if args.list_shares or args.setup_shares is not None or args.remove_shares:
            run_shares_command(args)
            return
        if args.login_user_list:
            if not is_joined():
                raise RuntimeError('This system is not joined to a UCS domain.')
            login_users.set_mode(args.login_user_list)
            return

        check_system()
        dc_ip = resolve_dc_ip(args.domain, args.dc_ip)
        pin_host_keys(dc_ip, args.dc_fingerprint, confirm_host_key)

        username = args.username or input('Domain administrator username: ')
        password = resolve_password(args)
        if password is None:
            password = getpass.getpass('Domain administrator password: ')

        joiner = connect_to_dc(dc_ip, username, password, args.skip_login_manager, args.force_ucs_dns)
        run_join(joiner)
    except SystemExit:
        raise
    except Exception as exc:
        if args.leave_domain:
            action = 'Leaving the domain'
        elif args.list_shares or args.setup_shares is not None or args.remove_shares:
            action = 'Share setup'
        elif args.login_user_list:
            action = 'Login screen setup'
        else:
            action = 'Domain join'
        userinfo_logger.critical('%s failed: %s. See %s for details.', action, str(exc).rstrip('.'), args.logfile)
        debug_logger.exception('%s failed', action)
        sys.exit(1)


if __name__ == '__main__':
    main()
