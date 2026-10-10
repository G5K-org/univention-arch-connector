#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 univention-arch-connector contributors
# SPDX-License-Identifier: AGPL-3.0-only
#
# New module, with no upstream equivalent: mounting UCS file shares at
# login. The shares defined in UCS (UDM shares/share objects with a Samba
# name) are read from LDAP with the machine account, so no admin
# credentials are needed. Selected shares, plus each user's Samba home
# share (sambaHomePath) if one is set in UCS, become pam_mount volumes:
# mounted via CIFS with the user's own Kerberos ticket (sec=krb5) under
# ~/Freigaben/<name> at login, and unmounted at logout. The volumes live in
# a marker-delimited block in /etc/security/pam_mount.conf.xml, which
# --leave-domain removes again. See ../NOTICE.md.

import configparser
import logging
import re
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple
from xml.etree import ElementTree
from xml.sax.saxutils import quoteattr

import ldap

from univention_arch_connector.distributions import DomainJoinException
from univention_arch_connector.join_steps.pam_configurator import PamConfigurator
from univention_arch_connector.join_steps.root_certificate_provider import CA_CERT_PATH
from univention_arch_connector.join_steps.sssd_configurator import SSSD_CONF, SssdConfigurator
from univention_arch_connector.utils.general import execute_as_root

userinfo_logger = logging.getLogger('userinfo')

PAM_MOUNT_CONF = Path('/etc/security/pam_mount.conf.xml')
PAM_MOUNT_MODULE = Path('/usr/lib/security/pam_mount.so')
MOUNT_DIR = '~/Freigaben'
BEGIN = '<!-- BEGIN univention-arch-connector (shares) -->'
END = '<!-- END univention-arch-connector (shares) -->'
# pam_mount expands %(USERUID)/%(USERGID). cruid makes cifs.upcall use that
# user's Kerberos ticket from /tmp/krb5cc_<uid>.
MOUNT_OPTIONS = 'sec=krb5,cruid=%(USERUID),uid=%(USERUID),gid=%(USERGID),nosuid,nodev'
FALLBACK_DOMAIN_USERS_GROUP = 'Domain Users'

# Programs mounting needs, and the Arch package providing each.
REQUIRED_PROGRAMS = {
    'mount.cifs': 'cifs-utils',
    'cifs.upcall': 'cifs-utils',
    'request-key': 'keyutils',
}


@dataclass(frozen=True)
class Share:
    name: str  # the Samba share name
    host: str


@dataclass(frozen=True)
class HomeShare:
    user: str
    host: str
    path: str  # share name plus optional subdirectory, e.g. "homes/alice"


def check_requirements() -> None:
    missing = sorted({package for program, package in REQUIRED_PROGRAMS.items() if not shutil.which(program)})
    if not PAM_MOUNT_MODULE.exists():
        missing.append('pam_mount')
    if missing:
        raise DomainJoinException('Mounting shares needs more packages. Install them with: pacman -S %s' % (' '.join(missing),))


@execute_as_root
def _sssd_domain_settings() -> Dict[str, str]:
    if not SSSD_CONF.exists():
        raise DomainJoinException('This system is not joined to a UCS domain (%s is missing).' % (SSSD_CONF,))
    parser = configparser.ConfigParser(interpolation=None)
    parser.read_string(SSSD_CONF.read_text())
    for section in parser.sections():
        if section.startswith('domain/'):
            return dict(parser[section])
    raise DomainJoinException('No domain section in %s.' % (SSSD_CONF,))


def _connect() -> Tuple['ldap.ldapobject.LDAPObject', str]:
    """Bind to the UCS LDAP server as this machine, like SSSD does."""
    settings = _sssd_domain_settings()
    connection = ldap.initialize(settings['ldap_uri'])
    connection.set_option(ldap.OPT_NETWORK_TIMEOUT, 10)
    connection.set_option(ldap.OPT_X_TLS_CACERTFILE, str(CA_CERT_PATH))
    connection.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_DEMAND)
    connection.set_option(ldap.OPT_X_TLS_NEWCTX, 0)
    connection.start_tls_s()
    connection.simple_bind_s(settings['ldap_default_bind_dn'], settings['ldap_default_authtok'])
    return connection, settings['ldap_search_base']


def _search(filterstr: str, attributes: List[str]) -> List[Dict[str, str]]:
    connection, base = _connect()
    try:
        results = connection.search_s(base, ldap.SCOPE_SUBTREE, filterstr, attributes)
    finally:
        connection.unbind_s()
    return [
        {key: values[0].decode() for key, values in attrs.items()}
        for dn, attrs in results if dn
    ]


def parse_unc(unc: str) -> Optional[Tuple[str, str]]:
    r"""Split \\host\share\sub into ("host", "share/sub")."""
    parts = [part for part in re.split(r'[\\/]+', unc.strip()) if part]
    if len(parts) < 2:
        return None
    return parts[0], '/'.join(parts[1:])


def list_shares() -> List[Share]:
    entries = _search('(objectClass=univentionShareSamba)', ['univentionShareSambaName', 'univentionShareHost'])
    shares = {
        Share(entry['univentionShareSambaName'], entry['univentionShareHost'])
        for entry in entries if 'univentionShareSambaName' in entry and 'univentionShareHost' in entry
    }
    return sorted(shares, key=lambda share: share.name.lower())


def list_home_shares() -> List[HomeShare]:
    entries = _search('(&(objectClass=sambaSamAccount)(uid=*)(sambaHomePath=*))', ['uid', 'sambaHomePath'])
    homes = []
    for entry in entries:
        parsed = parse_unc(entry['sambaHomePath'])
        if parsed:
            homes.append(HomeShare(entry['uid'], *parsed))
    return sorted(homes, key=lambda home: home.user.lower())


def domain_users_group() -> str:
    """The (possibly localized) name of UCS' "Domain Users" group."""
    entries = _search('(&(objectClass=posixGroup)(sambaSID=*-513))', ['cn'])
    return entries[0]['cn'] if entries else FALLBACK_DOMAIN_USERS_GROUP


def volume_lines(shares: Sequence[Share], homes: Sequence[HomeShare], group: str) -> List[str]:
    lines = []
    for share in shares:
        lines.append('<volume sgrp=%s fstype="cifs" server=%s path=%s mountpoint=%s options=%s />\n' % (
            quoteattr(group), quoteattr(share.host), quoteattr(share.name),
            quoteattr('%s/%s' % (MOUNT_DIR, share.name)), quoteattr(MOUNT_OPTIONS),
        ))
    for home in homes:
        lines.append('<volume user=%s fstype="cifs" server=%s path=%s mountpoint=%s options=%s />\n' % (
            quoteattr(home.user), quoteattr(home.host), quoteattr(home.path),
            quoteattr('%s/%s' % (MOUNT_DIR, home.path.split('/')[0])), quoteattr(MOUNT_OPTIONS),
        ))
    return lines


def _without_block(lines: List[str]) -> List[str]:
    out, inside = [], False
    for line in lines:
        if line.strip() == BEGIN:
            inside = True
        elif line.strip() == END:
            inside = False
        elif not inside:
            out.append(line)
    return out


def _write_volumes_impl(volumes: List[str]) -> None:
    lines = _without_block(PAM_MOUNT_CONF.read_text().splitlines(keepends=True))
    if volumes:
        closing = max((i for i, line in enumerate(lines) if line.strip() == '</pam_mount>'), default=None)
        if closing is None:
            raise DomainJoinException('%s has no </pam_mount> element.' % (PAM_MOUNT_CONF,))
        lines[closing:closing] = [BEGIN + '\n', *volumes, END + '\n']
    content = ''.join(lines)
    ElementTree.fromstring(content.encode())  # never write a file pam_mount can't parse
    PAM_MOUNT_CONF.write_text(content)


@execute_as_root
def _write_volumes(volumes: List[str]) -> None:
    _write_volumes_impl(volumes)


def configured_share_names() -> List[str]:
    """Names of the shares (not home shares) currently set up."""
    if not PAM_MOUNT_CONF.exists():
        return []
    lines = PAM_MOUNT_CONF.read_text().splitlines()
    names, inside = [], False
    for line in lines:
        if line.strip() == BEGIN:
            inside = True
        elif line.strip() == END:
            inside = False
        elif inside and line.lstrip().startswith('<volume sgrp='):
            names.append(ElementTree.fromstring(line.strip()).attrib['path'])
    return names


def setup_shares(names: Sequence[str]) -> None:
    """Mount the shares ``names`` (and everyone's home share) at login.
    An empty ``names`` still sets up home shares.
    """
    check_requirements()
    available = {share.name: share for share in list_shares()}
    unknown = [name for name in names if name not in available]
    if unknown:
        raise DomainJoinException('Unknown share(s): %s. Available: %s' % (
            ', '.join(unknown), ', '.join(available) or 'none'))
    shares = [available[name] for name in names]
    homes = list_home_shares()
    volumes = volume_lines(shares, homes, domain_users_group())

    SssdConfigurator().ensure_default_ccache_location()
    _write_volumes(volumes)
    if volumes:
        PamConfigurator().enable_pam_mount()
        for share in shares:
            userinfo_logger.info('Mounting //%s/%s at %s/%s for domain users', share.host, share.name, MOUNT_DIR, share.name)
        if homes:
            userinfo_logger.info('Mounting the home share of %d user(s) who have one in UCS', len(homes))
        userinfo_logger.info('Shares are mounted at the next login.')
    else:
        PamConfigurator().disable_pam_mount()
        userinfo_logger.info('No shares selected and no home shares in UCS; nothing is mounted.')


def remove_shares() -> None:
    if PAM_MOUNT_CONF.exists() and BEGIN in PAM_MOUNT_CONF.read_text():
        _write_volumes([])
        userinfo_logger.info('Removed the share configuration from %s', PAM_MOUNT_CONF)
    PamConfigurator().disable_pam_mount()
