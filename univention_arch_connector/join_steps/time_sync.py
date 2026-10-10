#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2025 univention-arch-connector contributors
# SPDX-License-Identifier: AGPL-3.0-only
#
# New module, split out of upstream's `kerberos_configurator.py` (where it
# was a single `ntpdate -b -u -t 5 <dc_ip>` call). Arch's official repos no
# longer ship a standalone `ntpdate` binary, so this tries a one-shot
# `chrony` sync first (the default time daemon on many Arch/CachyOS
# installs), falling back to `ntpd -gq` from the `ntp` package. Kerberos is
# clock-skew sensitive, so this runs before `kerberos_configurator`/`sssd`
# are relied upon - but unlike upstream's unguarded call, a failure here is
# logged and treated as non-fatal rather than aborting the whole join,
# since a client whose clock is already reasonably close to the DC's can
# often still complete the join. Containers share the host's clock and
# can't set it, so time sync is skipped there. See ../../NOTICE.md.

import logging
import shutil
import subprocess

from univention_arch_connector.utils.general import execute_as_root

userinfo_logger = logging.getLogger('userinfo')

TIMEOUT_SECONDS = 15


def sync_time(dc_ip: str) -> None:
    if _running_in_container():
        userinfo_logger.info('Running in a container, which uses the host\'s clock; skipping time synchronization')
    elif shutil.which('chronyd'):
        _sync_via_chrony(dc_ip)
    elif shutil.which('ntpd'):
        _sync_via_ntpd(dc_ip)
    else:
        userinfo_logger.warning(
            'Neither chrony nor ntp is installed; skipping time synchronization with the '
            'domain controller. Kerberos authentication may fail if the clocks are too far apart.'
        )


def _running_in_container() -> bool:
    try:
        return subprocess.run(['systemd-detect-virt', '--container', '--quiet'], check=False).returncode == 0
    except OSError:
        return False


@execute_as_root
def _sync_via_chrony(dc_ip: str) -> None:
    userinfo_logger.info('Synchronizing time with the domain controller via chrony')
    try:
        subprocess.check_output(
            ['chronyd', '-q', 'server %s iburst maxsamples 1' % (dc_ip,)],
            stderr=subprocess.STDOUT, timeout=TIMEOUT_SECONDS,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        userinfo_logger.warning('Time synchronization via chrony failed, continuing anyway: %s', exc)


@execute_as_root
def _sync_via_ntpd(dc_ip: str) -> None:
    userinfo_logger.info('Synchronizing time with the domain controller via ntpd')
    try:
        subprocess.check_output(
            ['ntpd', '-gq', '-p', dc_ip],
            stderr=subprocess.STDOUT, timeout=TIMEOUT_SECONDS,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        userinfo_logger.warning('Time synchronization via ntpd failed, continuing anyway: %s', exc)
