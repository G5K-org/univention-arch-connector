#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2025 univention-arch-connector contributors
# SPDX-License-Identifier: AGPL-3.0-only
#
# New module, with no upstream equivalent (upstream has no leave/undo
# path at all). Reverses a previous join using the backup manifest written
# by create_backup_of_config_files(): marker-delimited files
# (/etc/pam.d/system-login, /etc/security/group.conf, /etc/nsswitch.conf)
# are stripped surgically so unrelated manual edits made after joining
# aren't clobbered; every other touched file is restored verbatim (or
# deleted, if the join created it) from the manifest. Deliberately does
# NOT delete the computer object from UCS LDAP - that's a destructive
# remote action requiring admin credentials again, so it's left to the
# admin to do manually via UMC. See ../../NOTICE.md.

import logging
import shutil
import subprocess
from pathlib import Path
from typing import Optional

from univention_arch_connector.join_steps.nsswitch_configurator import NSSWITCH_CONF, NsswitchConfigurator
from univention_arch_connector.join_steps.pam_configurator import GROUP_CONF, PamConfigurator, SYSTEM_AUTH, SYSTEM_LOGIN
from univention_arch_connector.join_steps.sssd_configurator import SSSD_CONF
from univention_arch_connector.utils.backup import find_latest_backup_dir, load_manifest, restore_file
from univention_arch_connector.utils.general import execute_as_root

userinfo_logger = logging.getLogger('userinfo')

# These are handled by surgical marker removal above rather than a plain
# restore, since they're shared files other packages/the user may also
# have edited.
_MARKER_BASED_PATHS = {str(SYSTEM_AUTH), str(SYSTEM_LOGIN), str(GROUP_CONF), str(NSSWITCH_CONF)}


@execute_as_root
def _reload_services() -> None:
    subprocess.call(['update-ca-trust', 'extract'])
    if shutil.which('dconf'):  # only present with GDM/GNOME
        subprocess.call(['dconf', 'update'])
    if SSSD_CONF.exists():
        subprocess.call(['systemctl', 'restart', 'sssd'])
    else:
        subprocess.call(['systemctl', 'disable', '--now', 'sssd'])


def leave_domain(backup_dir: Optional[Path] = None) -> None:
    if backup_dir is None:
        backup_dir = find_latest_backup_dir()
        if backup_dir is None:
            raise RuntimeError(
                'No backup directory found; there is nothing for --leave-domain to undo. '
                'Pass --backup-dir explicitly if you know where it is.'
            )

    userinfo_logger.info('Leaving the domain using the backup at %s', backup_dir)
    manifest = load_manifest(backup_dir)

    PamConfigurator().remove()
    NsswitchConfigurator().remove()

    for entry in manifest:
        if entry['original_path'] in _MARKER_BASED_PATHS:
            continue
        restore_file(entry, backup_dir)

    _reload_services()

    userinfo_logger.info(
        'Left the domain. The computer object in UCS was NOT removed automatically - '
        'remove it manually via UMC if desired. A reboot is recommended.'
    )
