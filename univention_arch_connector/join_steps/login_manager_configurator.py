#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2025 univention-arch-connector contributors
# SPDX-License-Identifier: AGPL-3.0-only
#
# New module, replacing upstream's `login_manager_configurator.py`, which
# detects the active display manager by reading Debian's
# `/etc/X11/default-display-manager`. Arch has no such file; instead this
# follows the systemd-standard convention of resolving the
# `display-manager.service` symlink, which works uniformly for SDDM, GDM,
# LightDM and Plasma Login. See ../../NOTICE.md.
#
# Plasma Login (plasma-login-manager, KDE's successor to SDDM) needs no
# change: its PAM service includes system-login, so pam_sss, pam_mkhomedir
# and pam_mount apply, and its greeter offers "Type in Username and
# Password" for users not in its list (which only shows local users).
# Verified by running its PAM service (from plasma-login-manager 6.7.5)
# for a domain user; the greeter itself is untested.
#
# Known open items to verify against real installs during QA (see plan):
# - GDM's exact mechanism for allowing login with a username not in the
#   local user list (dconf override below is the documented approach, but
#   has not yet been verified against a live GDM greeter).
# - Whether SDDM needs any configuration at all for this (it is assumed to
#   already present a manual-username field for unlisted users by default).

import logging
import os
import subprocess
from pathlib import Path
from typing import Optional

from univention_arch_connector.distributions import DomainJoinException
from univention_arch_connector.utils.backup import Backup
from univention_arch_connector.utils.general import execute_as_root

userinfo_logger = logging.getLogger('userinfo')

DISPLAY_MANAGER_SERVICE_LINK = Path('/etc/systemd/system/display-manager.service')

SUPPORTED_LOGIN_MANAGERS = {'sddm', 'gdm', 'lightdm', 'plasmalogin'}

LIGHTDM_CONF_D = Path('/etc/lightdm/lightdm.conf.d')
LIGHTDM_MANUAL_LOGIN_CONF = LIGHTDM_CONF_D / '99-show-manual-userlogin.conf'
LIGHTDM_KDE_GREETER_CONF = Path('/etc/lightdm/lightdm-kde-greeter.conf')

GDM_DCONF_DB_D = Path('/etc/dconf/db/gdm.d')
GDM_DISABLE_USER_LIST_CONF = GDM_DCONF_DB_D / '01-univention-arch-connector'


def detect_login_manager() -> Optional[str]:
    """Return the short service name of the configured display manager
    (e.g. "sddm", "gdm", "lightdm"), or None if no display-manager.service
    is configured (headless/console-only system - nothing to do here).
    """
    if not DISPLAY_MANAGER_SERVICE_LINK.exists():
        return None
    target = Path(os.path.realpath(DISPLAY_MANAGER_SERVICE_LINK))
    return target.stem


def _lightdm_kde_greeter_is_installed() -> bool:
    return 0 == subprocess.call(
        ['pacman', '-Qi', 'lightdm-kde-greeter'],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )


def _lightdm_kde_theme_is_classic() -> bool:
    if not LIGHTDM_KDE_GREETER_CONF.is_file():
        return True
    for line in LIGHTDM_KDE_GREETER_CONF.read_text().splitlines():
        if 'theme-name' in line:
            return line.split('=', 1)[-1].strip() == 'classic'
    return True


class LoginManagerConfigurator:
    def check_for_conflicts(self, skip_login_manager: bool) -> None:
        if skip_login_manager:
            return
        login_manager = detect_login_manager()
        if login_manager is None:
            return
        if login_manager not in SUPPORTED_LOGIN_MANAGERS:
            # New login managers keep appearing (plasma-login-manager,
            # greetd, cosmic-greeter, ...). Not knowing one must not block
            # the join: domain logins work through PAM regardless, only
            # typing a name that isn't in the user list may need checking.
            userinfo_logger.warning(
                "Login manager '%s' is not known to this tool and is left unchanged. Domain logins "
                "work through PAM, but check that it lets you type a username that isn't listed. "
                "Known: %s.", login_manager, ', '.join(sorted(SUPPORTED_LOGIN_MANAGERS)),
            )
            return
        if login_manager == 'lightdm' and _lightdm_kde_greeter_is_installed() and not _lightdm_kde_theme_is_classic():
            raise DomainJoinException(
                "LightDM's KDE greeter theme is not set to 'classic', which is incompatible "
                "with domain login. Set it to 'classic', or rerun with --skip-login-manager."
            )

    @execute_as_root
    def backup(self, backup: Backup, skip_login_manager: bool) -> None:
        if skip_login_manager:
            return
        login_manager = detect_login_manager()
        if login_manager == 'lightdm':
            backup.backup_file(str(LIGHTDM_MANUAL_LOGIN_CONF))
        elif login_manager == 'gdm':
            backup.backup_file(str(GDM_DISABLE_USER_LIST_CONF))

    def enable_login_with_foreign_usernames(self) -> None:
        login_manager = detect_login_manager()
        if login_manager == 'lightdm':
            self._configure_lightdm()
        elif login_manager == 'gdm':
            self._configure_gdm()
        elif login_manager == 'sddm':
            userinfo_logger.info('SDDM already allows login with usernames outside the local user list; no change needed.')
        elif login_manager == 'plasmalogin':
            userinfo_logger.info(
                'Plasma Login needs no change: domain users log in via "Type in Username and Password" at the greeter.'
            )

    @execute_as_root
    def _configure_lightdm(self) -> None:
        userinfo_logger.info('Writing %s', LIGHTDM_MANUAL_LOGIN_CONF)
        LIGHTDM_CONF_D.mkdir(parents=True, exist_ok=True)
        LIGHTDM_MANUAL_LOGIN_CONF.write_text(
            '[SeatDefaults]\n'
            'greeter-show-manual-login=true\n'
            'greeter-hide-users=true\n'
        )

    @execute_as_root
    def _configure_gdm(self) -> None:
        userinfo_logger.info('Writing %s', GDM_DISABLE_USER_LIST_CONF)
        GDM_DCONF_DB_D.mkdir(parents=True, exist_ok=True)
        GDM_DISABLE_USER_LIST_CONF.write_text(
            '[org/gnome/login-screen]\n'
            'disable-user-list=true\n'
        )
        subprocess.check_output(['dconf', 'update'], stderr=subprocess.STDOUT)

    @execute_as_root
    def remove(self) -> None:
        if LIGHTDM_MANUAL_LOGIN_CONF.exists():
            LIGHTDM_MANUAL_LOGIN_CONF.unlink()
        if GDM_DISABLE_USER_LIST_CONF.exists():
            GDM_DISABLE_USER_LIST_CONF.unlink()
            subprocess.check_output(['dconf', 'update'], stderr=subprocess.STDOUT)
