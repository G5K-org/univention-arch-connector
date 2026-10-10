# Notice

This project is an **unofficial, community-maintained port** of
[`univention-domain-join`](https://github.com/univention/univention-domain-join)
(Copyright © 2017-2025 Univention GmbH, licensed under the
[GNU Affero General Public License v3.0 only](LICENSES/AGPL-3.0-only.txt))
to Arch Linux and Arch-based distributions (Arch Linux, CachyOS, EndeavourOS,
Manjaro, ...).

It is not affiliated with, endorsed by, or supported by Univention GmbH.
"Univention" and "UCS" are trademarks of Univention GmbH.

Several modules in this project (`utils/general.py`, `utils/ldap.py`,
`utils/domain.py`, `distributions/__init__.py`, parts of
`join_steps/ldap_configurator.py`, `join_steps/kerberos_configurator.py` and
`join_steps/root_certificate_provider.py`) are ported from the upstream
project, since that logic talks to the remote UCS domain controller only and
makes few assumptions about the client's Linux distribution. Each file's
header lists what was changed. The original SPDX copyright headers on that
code are preserved.

Modules that replace Debian/Ubuntu-specific mechanisms with Arch-native
ones (`join_steps/pam_configurator.py`, `join_steps/nsswitch_configurator.py`,
`join_steps/login_manager_configurator.py`, `join_steps/dns_configurator.py`,
`join_steps/time_sync.py`, `distributions/arch.py`), as well as
`join.py`, `join_info.py`, `shares.py`, `login_users.py`, `utils/host_key.py` and `leave/leave_domain.py`, are new code
written for this project and carry this project's own copyright/SPDX headers.

As a derivative work, this entire project is distributed under the same
license as upstream: AGPL-3.0-only. See [LICENSES/AGPL-3.0-only.txt](LICENSES/AGPL-3.0-only.txt).
