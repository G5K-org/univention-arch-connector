#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2017-2025 Univention GmbH
# SPDX-License-Identifier: AGPL-3.0-only
#
# Ported verbatim from univention-domain-join (upstream module:
# univention_domain_join/distributions/__init__.py). AbstractJoiner defines
# the distro-agnostic contract that concrete Joiner implementations (e.g.
# ArchJoiner) fulfil. See ../../NOTICE.md.

from typing import Dict


class AbstractJoiner:
    def __init__(
        self,
        ucr_variables: Dict[str, str],
        admin_username: str,
        admin_pw: str,
        dc_ip: str,
        skip_login_manager: bool,
        force_ucs_dns: bool,
    ) -> None:
        self.ucr_variables = ucr_variables
        self.admin_username = admin_username
        self.admin_pw = admin_pw
        self.dc_ip = dc_ip
        self.skip_login_manager = skip_login_manager
        self.force_ucs_dns = force_ucs_dns

    def check_if_join_is_possible_without_problems(self) -> None:
        """Raise an exception if a known, unresolvable conflict would
        prevent the join from succeeding (e.g. an unsupported login
        manager), *before* any system file has been changed.
        """
        raise NotImplementedError

    def create_backup_of_config_files(self) -> None:
        """Back up every configuration file that ``join_domain`` is about
        to change, so the join can be reviewed or reverted later.
        """
        raise NotImplementedError

    def join_domain(self) -> None:
        """Perform the actual domain join."""
        raise NotImplementedError


class DomainJoinException(Exception):
    pass


class DcResolveException(DomainJoinException):
    pass
