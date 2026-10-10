#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 univention-arch-connector contributors
# SPDX-License-Identifier: AGPL-3.0-only
#
# New module, with no upstream equivalent: mounting UCS file shares at
# login. The shares defined in UCS (UDM shares/share objects with a Samba
# name) are read from LDAP with the machine account, so no admin
# credentials are needed. Selected shares become pam_mount volumes: mounted
# via CIFS with the user's own Kerberos ticket (sec=krb5) under
# ~/Freigaben/<name> at login, and unmounted at logout.
#
# Optionally (--mount-home at join), each domain user's network home is
# mounted at ~/Freigaben/Home: the one Windows clients get from UCS'
# samba/homedirserver and samba/homedirpath (\\server\<user> through
# Samba's [homes] share), or the user's own sambaHomePath if UCS sets one.
#
# Volumes are selected by UID rather than user name, since PAM passes the
# name as typed, e.g. user@domain. Shares and the home mount live in two
# marker-delimited blocks in /etc/security/pam_mount.conf.xml, which
# --leave-domain removes again. See ../NOTICE.md.

import configparser
import logging
import re
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple
from xml.etree import ElementTree
from xml.sax.saxutils import escape, quoteattr

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
HOME_MOUNTPOINT = MOUNT_DIR + '/Home'
BEGIN = '<!-- BEGIN univention-arch-connector (shares) -->'
END = '<!-- END univention-arch-connector (shares) -->'
HOME_BEGIN = '<!-- BEGIN univention-arch-connector (home) -->'
HOME_END = '<!-- END univention-arch-connector (home) -->'
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
    """A user's own home share, from sambaHomePath."""
    user: str
    uid: int
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
    entries = _search('(&(objectClass=sambaSamAccount)(uid=*)(uidNumber=*)(sambaHomePath=*))',
                      ['uid', 'uidNumber', 'sambaHomePath'])
    homes = []
    for entry in entries:
        parsed = parse_unc(entry['sambaHomePath'])
        if parsed:
            homes.append(HomeShare(entry['uid'], int(entry['uidNumber']), *parsed))
    return sorted(homes, key=lambda home: home.user.lower())


def domain_users_group() -> str:
    """The (possibly localized) name of UCS' "Domain Users" group."""
    entries = _search('(&(objectClass=posixGroup)(sambaSID=*-513))', ['cn'])
    return entries[0]['cn'] if entries else FALLBACK_DOMAIN_USERS_GROUP


def volume_lines(shares: Sequence[Share], group: str) -> List[str]:
    return [
        '<volume sgrp=%s fstype="cifs" server=%s path=%s mountpoint=%s options=%s />\n' % (
            quoteattr(group), quoteattr(share.host), quoteattr(share.name),
            quoteattr('%s/%s' % (MOUNT_DIR, share.name)), quoteattr(MOUNT_OPTIONS),
        )
        for share in shares
    ]


def home_volume_lines(server: str, path: str, homes: Sequence[HomeShare], group: str) -> List[str]:
    """``server``/``path`` (e.g. %(USER)) for all domain users, except
    those with their own home share in ``homes``.
    """
    common = 'fstype="cifs" mountpoint=%s options=%s' % (quoteattr(HOME_MOUNTPOINT), quoteattr(MOUNT_OPTIONS))
    exceptions = ''.join('<not><uid>%d</uid></not>' % (home.uid,) for home in homes)
    lines = ['<volume server=%s path=%s %s><and><sgrp>%s</sgrp>%s</and></volume>\n' % (
        quoteattr(server), quoteattr(path), common, escape(group), exceptions,
    )]
    for home in homes:
        lines.append('<volume server=%s path=%s %s><uid>%d</uid></volume>\n' % (
            quoteattr(home.host), quoteattr(home.path), common, home.uid,
        ))
    return lines


def samba_home_location(homedirserver: str, homedirpath: str, domain: str, fallback_server: str) -> Tuple[str, str]:
    """Translate UCS' samba/homedirserver and samba/homedirpath (Samba
    syntax, e.g. "pdn01" and "%U") into a server name usable for Kerberos
    and a pam_mount path.
    """
    server = homedirserver.strip()
    if not server or '%' in server:
        server = fallback_server
    elif '.' not in server:
        server = '%s.%s' % (server, domain)
    path = re.sub(r'%[Uu]', '%(USER)', homedirpath.strip().replace('\\', '/').strip('/')) or '%(USER)'
    if re.search(r'%(?!\(USER\))', path):
        userinfo_logger.warning('Unsupported samba/homedirpath %r; using the user name as share', homedirpath)
        path = '%(USER)'
    return server, path


def _without_block(lines: List[str], begin: str = BEGIN, end: str = END) -> List[str]:
    out, inside = [], False
    for line in lines:
        if line.strip() == begin:
            inside = True
        elif line.strip() == end:
            inside = False
        elif not inside:
            out.append(line)
    return out


def _write_block_impl(begin: str, end: str, volumes: List[str]) -> None:
    lines = _without_block(PAM_MOUNT_CONF.read_text().splitlines(keepends=True), begin, end)
    if volumes:
        closing = max((i for i, line in enumerate(lines) if line.strip() == '</pam_mount>'), default=None)
        if closing is None:
            raise DomainJoinException('%s has no </pam_mount> element.' % (PAM_MOUNT_CONF,))
        lines[closing:closing] = [begin + '\n', *volumes, end + '\n']
    content = ''.join(lines)
    ElementTree.fromstring(content.encode())  # never write a file pam_mount can't parse
    PAM_MOUNT_CONF.write_text(content)


def _write_volumes_impl(volumes: List[str]) -> None:
    _write_block_impl(BEGIN, END, volumes)


@execute_as_root
def _write_block(begin: str, end: str, volumes: List[str]) -> None:
    _write_block_impl(begin, end, volumes)


@execute_as_root
def _sync_pam_mount() -> None:
    """pam_mount runs at login as long as one of our blocks exists."""
    content = PAM_MOUNT_CONF.read_text() if PAM_MOUNT_CONF.exists() else ''
    wanted = BEGIN in content or HOME_BEGIN in content
    if wanted != PamConfigurator().pam_mount_enabled():
        if wanted:
            PamConfigurator().enable_pam_mount()
        else:
            PamConfigurator().disable_pam_mount()


@execute_as_root
def home_mount_enabled() -> bool:
    return PAM_MOUNT_CONF.exists() and HOME_BEGIN in PAM_MOUNT_CONF.read_text()


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
    """Mount the shares ``names`` at login (an empty list stops mounting
    shares; the home mount is set at join, see setup_home_mount()).
    """
    check_requirements()
    available = {share.name: share for share in list_shares()}
    unknown = [name for name in names if name not in available]
    if unknown:
        raise DomainJoinException('Unknown share(s): %s. Available: %s' % (
            ', '.join(unknown), ', '.join(available) or 'none'))
    shares = [available[name] for name in names]

    SssdConfigurator().ensure_default_ccache_location()
    _write_block(BEGIN, END, volume_lines(shares, domain_users_group()))
    _sync_pam_mount()
    for share in shares:
        userinfo_logger.info('Mounting //%s/%s at %s/%s for domain users', share.host, share.name, MOUNT_DIR, share.name)
    userinfo_logger.info('Shares are mounted at the next login.' if shares else 'No shares are mounted at login.')


def remove_shares() -> None:
    if PAM_MOUNT_CONF.exists() and BEGIN in PAM_MOUNT_CONF.read_text():
        _write_block(BEGIN, END, [])
        userinfo_logger.info('Removed the share configuration from %s', PAM_MOUNT_CONF)
    _sync_pam_mount()


def setup_home_mount(server: str, path: str) -> None:
    """Mount each domain user's network home at ~/Freigaben/Home."""
    check_requirements()
    homes = list_home_shares()
    SssdConfigurator().ensure_default_ccache_location()
    _write_block(HOME_BEGIN, HOME_END, home_volume_lines(server, path, homes, domain_users_group()))
    _sync_pam_mount()
    userinfo_logger.info('Mounting each domain user\'s home //%s/%s at %s at login', server, path, HOME_MOUNTPOINT)
    for home in homes:
        userinfo_logger.info('  %s uses its own home share //%s/%s', home.user, home.host, home.path)


def remove_home_mount() -> None:
    if home_mount_enabled():
        _write_block(HOME_BEGIN, HOME_END, [])
        userinfo_logger.info('No longer mounting home directories at %s', HOME_MOUNTPOINT)
    _sync_pam_mount()
