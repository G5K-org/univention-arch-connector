# SPDX-FileCopyrightText: 2025 univention-arch-connector contributors
# SPDX-License-Identifier: AGPL-3.0-only

import pytest

from univention_arch_connector.distributions import DomainJoinException
from univention_arch_connector.join_steps import login_manager_configurator as lmc


def _fake_display_manager_service_link(tmp_path, target_name):
    """Build a fake display-manager.service symlink chain like the real
    systemd convention: /etc/systemd/system/display-manager.service ->
    /usr/lib/systemd/system/<target_name>.service (verified against a real
    Arch/CachyOS install, where it resolves to .../sddm.service).
    """
    real_unit = tmp_path / ('%s.service' % (target_name,))
    real_unit.write_text('[Unit]\n')
    link = tmp_path / 'display-manager.service'
    link.symlink_to(real_unit)
    return link


@pytest.mark.parametrize('dm', ['sddm', 'gdm', 'lightdm', 'plasmalogin'])
def test_detect_login_manager_supported(monkeypatch, tmp_path, dm):
    link = _fake_display_manager_service_link(tmp_path, dm)
    monkeypatch.setattr(lmc, 'DISPLAY_MANAGER_SERVICE_LINK', link)

    assert lmc.detect_login_manager() == dm


def test_detect_login_manager_none_when_no_display_manager(monkeypatch, tmp_path):
    monkeypatch.setattr(lmc, 'DISPLAY_MANAGER_SERVICE_LINK', tmp_path / 'does-not-exist')

    assert lmc.detect_login_manager() is None


@pytest.mark.parametrize('dm', ['greetd', 'cosmic-greeter'])
def test_unknown_login_manager_only_warns(monkeypatch, tmp_path, caplog, dm):
    link = _fake_display_manager_service_link(tmp_path, dm)
    monkeypatch.setattr(lmc, 'DISPLAY_MANAGER_SERVICE_LINK', link)

    lmc.LoginManagerConfigurator().check_for_conflicts(skip_login_manager=False)
    lmc.LoginManagerConfigurator().enable_login_with_foreign_usernames()

    assert "'%s' is not known" % (dm,) in caplog.text


def test_check_for_conflicts_passes_for_supported_managers(monkeypatch, tmp_path):
    link = _fake_display_manager_service_link(tmp_path, 'sddm')
    monkeypatch.setattr(lmc, 'DISPLAY_MANAGER_SERVICE_LINK', link)
    monkeypatch.setattr(lmc, '_lightdm_kde_greeter_is_installed', lambda: False)

    lmc.LoginManagerConfigurator().check_for_conflicts(skip_login_manager=False)  # must not raise


def test_check_for_conflicts_skipped_entirely_when_requested(monkeypatch, tmp_path):
    link = _fake_display_manager_service_link(tmp_path, 'xdm')
    monkeypatch.setattr(lmc, 'DISPLAY_MANAGER_SERVICE_LINK', link)

    lmc.LoginManagerConfigurator().check_for_conflicts(skip_login_manager=True)  # must not raise


def test_lightdm_kde_classic_theme_conflict_detected(monkeypatch, tmp_path):
    link = _fake_display_manager_service_link(tmp_path, 'lightdm')
    monkeypatch.setattr(lmc, 'DISPLAY_MANAGER_SERVICE_LINK', link)
    monkeypatch.setattr(lmc, '_lightdm_kde_greeter_is_installed', lambda: True)

    greeter_conf = tmp_path / 'lightdm-kde-greeter.conf'
    greeter_conf.write_text('[General]\ntheme-name=oxygen\n')
    monkeypatch.setattr(lmc, 'LIGHTDM_KDE_GREETER_CONF', greeter_conf)

    with pytest.raises(DomainJoinException):
        lmc.LoginManagerConfigurator().check_for_conflicts(skip_login_manager=False)


def test_lightdm_kde_classic_theme_no_conflict(monkeypatch, tmp_path):
    link = _fake_display_manager_service_link(tmp_path, 'lightdm')
    monkeypatch.setattr(lmc, 'DISPLAY_MANAGER_SERVICE_LINK', link)
    monkeypatch.setattr(lmc, '_lightdm_kde_greeter_is_installed', lambda: True)

    greeter_conf = tmp_path / 'lightdm-kde-greeter.conf'
    greeter_conf.write_text('[General]\ntheme-name=classic\n')
    monkeypatch.setattr(lmc, 'LIGHTDM_KDE_GREETER_CONF', greeter_conf)

    lmc.LoginManagerConfigurator().check_for_conflicts(skip_login_manager=False)  # must not raise


def test_plasma_login_is_supported_without_changes(monkeypatch, tmp_path, caplog):
    link = _fake_display_manager_service_link(tmp_path, 'plasmalogin')
    monkeypatch.setattr(lmc, 'DISPLAY_MANAGER_SERVICE_LINK', link)
    caplog.set_level('INFO')

    configurator = lmc.LoginManagerConfigurator()
    configurator.check_for_conflicts(skip_login_manager=False)
    configurator.enable_login_with_foreign_usernames()

    assert 'not known' not in caplog.text
    assert 'Type in Username and Password' in caplog.text
