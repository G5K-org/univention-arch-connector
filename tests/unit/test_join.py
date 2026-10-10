# SPDX-FileCopyrightText: 2026 univention-arch-connector contributors
# SPDX-License-Identifier: AGPL-3.0-only

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from univention_arch_connector import join
from univention_arch_connector.distributions import DomainJoinException
from univention_arch_connector.distributions import arch
from univention_arch_connector.utils import ldap


def _fake_ssh(results):
    """ssh() stand-in returning (returncode, stdout, stderr) per command."""
    def ssh(username, password, hostname, command, **kwargs):
        returncode, stdout, stderr = results(command)
        process = MagicMock(returncode=returncode)
        process.communicate.return_value = (stdout, stderr)
        return process
    return ssh


def test_check_system_lists_missing_programs_and_packages(monkeypatch):
    monkeypatch.setattr(join, 'is_arch_based', lambda: True)
    monkeypatch.setattr(join.shutil, 'which', lambda program: None if program in ('sssd', 'ssh-keyscan') else '/usr/bin/x')
    with pytest.raises(DomainJoinException) as exc:
        join.check_system()
    assert 'ssh-keyscan, sssd' in str(exc.value)
    assert 'pacman -S openssh sssd' in str(exc.value)


def test_check_system_rejects_non_arch(monkeypatch):
    monkeypatch.setattr(join, 'is_arch_based', lambda: False)
    with pytest.raises(DomainJoinException, match='Arch'):
        join.check_system()


def test_run_join_rolls_back_and_reraises(monkeypatch):
    joiner = MagicMock()
    joiner.backup.backup_dir = Path('/var/backup/x')
    joiner.join_domain.side_effect = RuntimeError('boom')
    rollback = MagicMock()
    monkeypatch.setattr(join, 'rollback', rollback)

    with pytest.raises(RuntimeError, match='boom'):
        join.run_join(joiner)
    rollback.assert_called_once_with(Path('/var/backup/x'))


def test_run_join_rolls_back_on_ctrl_c(monkeypatch):
    joiner = MagicMock()
    joiner.join_domain.side_effect = KeyboardInterrupt
    rollback = MagicMock()
    monkeypatch.setattr(join, 'rollback', rollback)

    with pytest.raises(KeyboardInterrupt):
        join.run_join(joiner)
    rollback.assert_called_once()


def test_run_join_does_not_roll_back_on_success(monkeypatch):
    joiner = MagicMock()
    rollback = MagicMock()
    save = MagicMock()
    monkeypatch.setattr(join, 'rollback', rollback)
    monkeypatch.setattr(join.join_info, 'save', save)

    join.run_join(joiner, 'SHA256:abc')
    rollback.assert_not_called()
    save.assert_called_once_with(
        joiner.domain, joiner.ldap_server_name, joiner.dc_ip, 'SHA256:abc', joiner.admin_username,
        joiner.force_ucs_dns, joiner.skip_login_manager,
    )


def test_missing_required_ucr_variables_are_reported(monkeypatch):
    def results(command):
        if command[-1] in ('ldap/base', 'kerberos/realm'):
            return (1, b'', b'ucr: command not found')
        return (0, b'value\n', b'')
    monkeypatch.setattr(arch, 'ssh', _fake_ssh(results))

    with pytest.raises(DomainJoinException) as exc:
        arch.get_ucr_variables_from_dc('192.0.2.10', 'Administrator', 'secret')
    assert 'ldap/base, kerberos/realm' in str(exc.value)
    assert 'ucr: command not found' in str(exc.value)


def test_failed_kinit_on_the_dc_aborts(monkeypatch):
    monkeypatch.setattr(ldap, 'ssh', _fake_ssh(lambda command: (1, b'', b'kinit: Password incorrect')))
    with pytest.raises(DomainJoinException, match='Password incorrect'):
        ldap.authenticate_admin('192.0.2.10', 'Administrator', 'secret')


def test_successful_kinit_with_warnings_on_stderr_continues(monkeypatch):
    monkeypatch.setattr(ldap, 'ssh', _fake_ssh(lambda command: (0, b'', b'some warning')))
    ldap.authenticate_admin('192.0.2.10', 'Administrator', 'secret')


def test_time_sync_is_skipped_in_containers(monkeypatch):
    from univention_arch_connector.join_steps import time_sync
    monkeypatch.setattr(time_sync, '_running_in_container', lambda: True)
    monkeypatch.setattr(time_sync, '_sync_via_chrony', MagicMock(side_effect=AssertionError('should not sync')))
    time_sync.sync_time('192.0.2.10')


def test_computer_objects_are_looked_up_by_short_hostname(monkeypatch):
    from univention_arch_connector.utils import general
    monkeypatch.setattr(general.socket, 'gethostname', lambda: 'client.site.example.com')
    commands = []

    def results(command):
        commands.append(command)
        return (0, b'', b'')
    process_ssh = _fake_ssh(results)

    def ssh(*args, **kwargs):
        process = process_ssh(*args, **kwargs)
        process.stdout = iter([b'DN: cn=client,cn=computers,dc=example,dc=com\n'])
        return process
    monkeypatch.setattr(ldap, 'ssh', ssh)

    ldap.get_machines_ldap_dn_given_the_udm_type('computers/linux', '192.0.2.10', 'Administrator', 'secret', 'uid=Administrator')
    assert commands[0][-1] == 'name=client'


def test_admin_password_file_is_private_and_unpredictable():
    path = ldap.PW('Administrator')
    assert path.startswith('/dev/shm/univention-arch-connector-') and len(path) > len('/dev/shm/univention-arch-connector-') + 16
    assert 'Administrator' not in path


def test_admin_password_file_is_created_private_and_never_overwritten(monkeypatch):
    commands = []

    def results(command):
        commands.append(command)
        return (0, b'', b'')
    monkeypatch.setattr(ldap, 'ssh', _fake_ssh(results))

    ldap.authenticate_admin('192.0.2.10', 'Administrator', 'secret')
    script = commands[0][4]
    assert script.startswith('umask 077; set -C; ')


def _joiner_for_dns_checks(monkeypatch, local, ucs):
    from univention_arch_connector.distributions import arch as arch_mod
    joiner = arch_mod.ArchJoiner.__new__(arch_mod.ArchJoiner)
    joiner.ldap_master = joiner.ldap_server_name = 'dc.example.com'
    monkeypatch.setattr(arch_mod, 'local_addresses_of', lambda name: set(local))
    monkeypatch.setattr(arch_mod, 'addresses_in_ucs_dns', lambda name, nameserver: set(ucs))
    return joiner


def test_dc_name_resolving_elsewhere_aborts_with_force_ucs_dns_hint(monkeypatch):
    from univention_arch_connector.distributions import DcResolveException
    # A public DNS server answering for the UCS domain, as seen on a client.
    joiner = _joiner_for_dns_checks(monkeypatch, ['2a06:98c1:3121::'], ['10.0.0.244'])
    with pytest.raises(DcResolveException, match='resolves to 2a06:98c1:3121:: on this system, but to 10.0.0.244.*--force-ucs-dns'):
        joiner.check_dc_names_resolve_to_the_dc(['10.0.0.244'])


def test_dc_name_resolving_to_the_dc_passes(monkeypatch):
    joiner = _joiner_for_dns_checks(monkeypatch, ['10.0.0.244', 'fd00::244'], ['10.0.0.244'])
    joiner.check_dc_names_resolve_to_the_dc(['10.0.0.244'])


def test_dc_name_check_is_skipped_without_reachable_ucs_dns(monkeypatch):
    joiner = _joiner_for_dns_checks(monkeypatch, ['192.0.2.1'], ['10.0.0.244'])
    joiner.check_dc_names_resolve_to_the_dc([])


def test_unresolvable_dc_name_aborts(monkeypatch):
    from univention_arch_connector.distributions import DcResolveException
    joiner = _joiner_for_dns_checks(monkeypatch, [], ['10.0.0.244'])
    with pytest.raises(DcResolveException, match='Could not resolve'):
        joiner.check_dc_names_resolve_to_the_dc(['10.0.0.244'])


def test_only_answering_ucs_nameservers_are_used(monkeypatch):
    from univention_arch_connector.utils import domain

    class FakeResolver:
        def __init__(self, configure=True):
            self.nameservers = []

        def resolve(self, name, record_type):
            if self.nameservers != ['10.0.0.244']:  # e.g. the DC's second, unreachable interface
                raise Exception('timeout')
            return []

    monkeypatch.setattr(domain.dns.resolver, 'Resolver', FakeResolver)
    assert domain.ucs_nameservers_answering(['10.0.0.244', '10.1.0.1', '10.0.0.244'], 'example.com') == ['10.0.0.244']


def test_rollback_of_a_rejoin_keeps_the_password_ucs_already_has(monkeypatch):
    from univention_arch_connector.distributions import arch as arch_mod
    joiner = arch_mod.ArchJoiner.__new__(arch_mod.ArchJoiner)
    joiner.ldap_configurator = MagicMock(password_set_on_dc='new-secret')
    joiner.sssd_configurator = MagicMock()
    joiner.backup = MagicMock(joined_before=True)

    joiner.keep_new_machine_password()

    joiner.ldap_configurator.create_machine_secret_file.assert_called_once_with('new-secret')
    joiner.sssd_configurator.update_machine_password.assert_called_once_with('new-secret')


@pytest.mark.parametrize('joined_before, password', [(False, 'new-secret'), (True, None)])
def test_rollback_leaves_config_alone_when_not_needed(joined_before, password):
    from univention_arch_connector.distributions import arch as arch_mod
    joiner = arch_mod.ArchJoiner.__new__(arch_mod.ArchJoiner)
    joiner.ldap_configurator = MagicMock(password_set_on_dc=password)
    joiner.sssd_configurator = MagicMock()
    joiner.backup = MagicMock(joined_before=joined_before)

    joiner.keep_new_machine_password()

    joiner.sssd_configurator.update_machine_password.assert_not_called()
