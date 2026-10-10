#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 univention-arch-connector contributors
# SPDX-License-Identifier: AGPL-3.0-only
#
# New module, with no upstream equivalent: what the last successful join
# used (no secrets), so the graphical assistant can tell that this system
# is already joined and prefill its form for a re-join. For systems joined
# before this was recorded, the values are derived from the configuration
# the join left behind. See ../NOTICE.md.

import configparser
import json
import re
import socket
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from univention_arch_connector.join_steps.dns_configurator import NETWORKMANAGER_DROP_IN, RESOLVED_DROP_IN
from univention_arch_connector.join_steps.sssd_configurator import SSSD_CONF
from univention_arch_connector.utils.general import execute_as_root

JOIN_INFO = Path('/var/lib/univention-arch-connector/join.json')


@execute_as_root
def save(
    domain: str, dc_host: str, dc_ip: str, dc_fingerprint: Optional[str], username: str,
    force_ucs_dns: bool, skip_login_manager: bool,
) -> None:
    info = {
        'domain': domain,
        'dc_host': dc_host,
        'dc_ip': dc_ip,
        'dc_fingerprint': dc_fingerprint,
        'username': username,
        'force_ucs_dns': force_ucs_dns,
        'skip_login_manager': skip_login_manager,
        'joined_at': datetime.now(timezone.utc).isoformat(timespec='seconds'),
    }
    JOIN_INFO.parent.mkdir(parents=True, exist_ok=True)
    JOIN_INFO.write_text(json.dumps(info, indent=2) + '\n')


@execute_as_root
def remove() -> None:
    if JOIN_INFO.exists():
        JOIN_INFO.unlink()


@execute_as_root
def load() -> Optional[Dict[str, Any]]:
    """What is known about the current join, or None if not joined."""
    if not SSSD_CONF.exists():
        return None
    try:
        return json.loads(JOIN_INFO.read_text())
    except (OSError, ValueError):
        return _derive_from_configuration()


def _derive_from_configuration() -> Dict[str, Any]:
    parser = configparser.ConfigParser(interpolation=None)
    parser.read_string(SSSD_CONF.read_text())
    section = next((s for s in parser.sections() if s.startswith('domain/')), None)
    settings = parser[section] if section else {}
    match = re.match(r'^ldaps?://([^:/]+)', settings.get('ldap_uri', ''))
    dc_host = match.group(1) if match else ''
    try:
        dc_ip = socket.gethostbyname(dc_host) if dc_host else ''
    except OSError:
        dc_ip = ''
    return {
        'domain': section[len('domain/'):] if section else '',
        'dc_host': dc_host,
        'dc_ip': dc_ip,
        'dc_fingerprint': None,
        'username': None,
        'force_ucs_dns': RESOLVED_DROP_IN.exists() or NETWORKMANAGER_DROP_IN.exists(),
        'skip_login_manager': False,
        'joined_at': None,
    }
