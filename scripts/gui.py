#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2025 univention-arch-connector contributors
# SPDX-License-Identifier: AGPL-3.0-only
#
# Lightly adapted from univention-domain-join (upstream module:
# scripts/gui.py). Same contract as upstream: a PyQt5 assistant that
# collects the admin credentials/options and then drives the same Joiner
# the CLI uses, launched elevated via polkit's pkexec (see
# data/*.policy and data/*.desktop) rather than reimplementing any
# privilege logic itself. See ../NOTICE.md.

import logging
import queue
import sys
from pathlib import Path
from typing import List, Optional

from PyQt5.QtCore import QObject, Qt, QThread, pyqtSignal
from PyQt5.QtWidgets import (
    QApplication, QCheckBox, QComboBox, QDialog, QFormLayout, QHBoxLayout, QLabel,
    QLineEdit, QMessageBox, QPlainTextEdit, QPushButton, QVBoxLayout,
)

from univention_arch_connector import admin_group, shares
from univention_arch_connector import join_info
from univention_arch_connector.join import already_joined_notice, check_system, connect_to_dc, resolve_dc_ip, run_join
from univention_arch_connector import login_users
from univention_arch_connector.join_steps.sssd_configurator import is_joined
from univention_arch_connector.utils.host_key import pin_host_keys

userinfo_logger = logging.getLogger('userinfo')
debug_logger = logging.getLogger('debugging')

LOGFILE = Path('/var/log/univention-arch-connector/domain-join-gui.log')


def set_up_file_logging() -> None:
    """Keep the log, including error details, for troubleshooting - the
    window only shows the progress messages.
    """
    try:
        LOGFILE.parent.mkdir(parents=True, exist_ok=True)
        handler = logging.FileHandler(LOGFILE)
    except OSError as exc:
        print('Not logging to %s: %s' % (LOGFILE, exc), file=sys.stderr)
        return
    handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(name)s: %(message)s'))
    userinfo_logger.setLevel(logging.INFO)
    userinfo_logger.addHandler(handler)
    debug_logger.setLevel(logging.DEBUG)
    debug_logger.addHandler(handler)


class QueueLogHandler(logging.Handler):
    def __init__(self, log_queue: "queue.Queue[str]") -> None:
        super().__init__()
        self.log_queue = log_queue

    def emit(self, record: logging.LogRecord) -> None:
        self.log_queue.put(self.format(record))


class JoinWorker(QObject):
    finished = pyqtSignal(bool, str)
    # Connected with a BlockingQueuedConnection: the dialog asks the user
    # in the GUI thread and stores the answer in host_key_accepted.
    host_key_confirmation_requested = pyqtSignal(str, list)

    def __init__(self, username: str, password: str, domain: str, dc_ip: str, dc_fingerprint: str,
                 skip_login_manager: bool, force_ucs_dns: bool, mount_home: bool, admin_group: str) -> None:
        super().__init__()
        self.username = username
        self.password = password
        self.domain = domain
        self.dc_ip = dc_ip
        self.dc_fingerprint = dc_fingerprint
        self.skip_login_manager = skip_login_manager
        self.force_ucs_dns = force_ucs_dns
        self.mount_home = mount_home
        self.admin_group = admin_group
        self.host_key_accepted = False

    def confirm_host_key(self, dc_ip: str, fingerprints: List[str]) -> bool:
        self.host_key_confirmation_requested.emit(dc_ip, fingerprints)
        return self.host_key_accepted

    def run(self) -> None:
        try:
            check_system()
            dc_ip = resolve_dc_ip(self.domain, self.dc_ip)
            dc_fingerprint = pin_host_keys(dc_ip, self.dc_fingerprint or None, self.confirm_host_key)
            joiner = connect_to_dc(
                dc_ip, self.username, self.password, self.skip_login_manager, self.force_ucs_dns, self.mount_home,
                self.admin_group,
            )
            run_join(joiner, dc_fingerprint)
        except Exception as exc:
            debug_logger.exception('Domain join failed')
            self.finished.emit(False, str(exc))
        else:
            self.finished.emit(True, '')


LOGIN_LIST_LABELS = {
    'hide': 'Local users only',
    'known': 'Domain users who logged in here before',
    'all': 'All domain users (small domains)',
}


class SharesDialog(QDialog):
    """Choose which UCS shares are mounted at login."""

    def __init__(self, parent: QDialog, available: List[shares.Share], configured: List[str], home_mounted: bool) -> None:
        super().__init__(parent)
        self.setWindowTitle('Network shares')
        layout = QVBoxLayout()
        layout.addWidget(QLabel('Mount these shares at login under %s/<name>:' % (shares.MOUNT_DIR,)))
        self.checkboxes = []
        for share in available:
            checkbox = QCheckBox('%s  (//%s/%s)' % (share.name, share.host, share.name))
            checkbox.setChecked(share.name in configured)
            checkbox.setProperty('share_name', share.name)
            layout.addWidget(checkbox)
            self.checkboxes.append(checkbox)
        if not available:
            layout.addWidget(QLabel('No shares are defined in UCS.'))
        layout.addWidget(QLabel(
            'Home directories: %s (set when joining).' % ('mounted at %s' % (shares.HOME_MOUNTPOINT,) if home_mounted else 'not mounted',)
        ))
        save_button = QPushButton('Save')
        save_button.clicked.connect(self.accept)
        cancel_button = QPushButton('Cancel')
        cancel_button.clicked.connect(self.reject)
        button_row = QHBoxLayout()
        button_row.addWidget(save_button)
        button_row.addWidget(cancel_button)
        layout.addLayout(button_row)
        self.setLayout(layout)

    def selected(self) -> List[str]:
        return [checkbox.property('share_name') for checkbox in self.checkboxes if checkbox.isChecked()]


class DomainJoinDialog(QDialog):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle('Join Univention Domain')
        self.setMinimumWidth(480)

        self.username_edit = QLineEdit()
        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.Password)
        self.domain_edit = QLineEdit()
        self.domain_edit.setPlaceholderText('auto-detected if left empty')
        self.dc_ip_edit = QLineEdit()
        self.dc_ip_edit.setPlaceholderText('auto-detected via DNS if left empty')
        self.dc_fingerprint_edit = QLineEdit()
        self.dc_fingerprint_edit.setPlaceholderText('SHA256:... - asked to confirm if left empty')
        self.skip_login_manager_checkbox = QCheckBox("Don't configure the login manager")
        self.force_ucs_dns_checkbox = QCheckBox("Point this system's DNS at the domain controller")
        self.mount_home_checkbox = QCheckBox("Mount each user's network home at %s" % (shares.HOME_MOUNTPOINT,))
        self.mount_home_checkbox.setChecked(shares.home_mount_enabled())
        self.admin_group_edit = QLineEdit(admin_group.configured_group() or '')
        self.admin_group_edit.setPlaceholderText('e.g. linux-admins - empty: none')
        self.login_list_combo = QComboBox()
        for mode, label in LOGIN_LIST_LABELS.items():
            self.login_list_combo.addItem(label, mode)
        self.login_list_combo.setToolTip('Takes effect immediately on a joined system.')
        joined = is_joined()
        self.login_list_combo.setEnabled(joined)
        if joined:
            self.login_list_combo.setCurrentIndex(list(LOGIN_LIST_LABELS).index(login_users.current_mode()))
        self.login_list_combo.currentIndexChanged.connect(self.set_login_list_mode)

        form = QFormLayout()
        form.addRow('Administrator username:', self.username_edit)
        form.addRow('Administrator password:', self.password_edit)
        form.addRow('Domain (optional):', self.domain_edit)
        form.addRow('Domain controller IP (optional):', self.dc_ip_edit)
        form.addRow('DC SSH host key fingerprint (optional):', self.dc_fingerprint_edit)
        form.addRow(self.skip_login_manager_checkbox)
        form.addRow(self.force_ucs_dns_checkbox)
        form.addRow(self.mount_home_checkbox)
        form.addRow('UCS group with admin (sudo) rights:', self.admin_group_edit)
        form.addRow('Login screen lists:', self.login_list_combo)

        self.log_view = QPlainTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setMinimumHeight(160)

        self.join_button = QPushButton('Join domain')
        self.join_button.clicked.connect(self.start_join)
        self.shares_button = QPushButton('Network shares…')
        self.shares_button.clicked.connect(self.edit_shares)
        self.shares_button.setEnabled(is_joined())
        self.close_button = QPushButton('Close')
        self.close_button.clicked.connect(self.reject)

        button_row = QHBoxLayout()
        button_row.addWidget(self.join_button)
        button_row.addWidget(self.shares_button)
        button_row.addWidget(self.close_button)

        self.notice_label = QLabel()
        self.notice_label.setWordWrap(True)
        self.notice_label.setStyleSheet('QLabel { border: 1px solid palette(mid); border-radius: 4px; padding: 6px; }')
        self.notice_label.setVisible(False)

        layout = QVBoxLayout()
        layout.addWidget(self.notice_label)
        layout.addLayout(form)
        layout.addWidget(QLabel('Log:'))
        layout.addWidget(self.log_view)
        layout.addLayout(button_row)
        self.setLayout(layout)

        self.log_queue: "queue.Queue[str]" = queue.Queue()
        handler = QueueLogHandler(self.log_queue)
        handler.setFormatter(logging.Formatter('%(message)s'))
        userinfo_logger.setLevel(logging.INFO)
        userinfo_logger.addHandler(handler)

        self.show_join_state()

        self._drain_timer_id = self.startTimer(200)
        self.thread: Optional[QThread] = None
        self.worker: Optional[JoinWorker] = None

    def show_join_state(self) -> None:
        """If already joined, say so and prefill the form for a re-join."""
        notice = already_joined_notice()
        self.notice_label.setVisible(bool(notice))
        if not notice:
            return
        self.notice_label.setText(notice)
        info = join_info.load() or {}
        for edit, key in ((self.username_edit, 'username'), (self.domain_edit, 'domain'),
                          (self.dc_ip_edit, 'dc_ip'), (self.dc_fingerprint_edit, 'dc_fingerprint')):
            if info.get(key) and not edit.text():
                edit.setText(info[key])
                edit.setCursorPosition(0)  # show the start of long values like the fingerprint
        self.force_ucs_dns_checkbox.setChecked(bool(info.get('force_ucs_dns')))
        self.skip_login_manager_checkbox.setChecked(bool(info.get('skip_login_manager')))
        self.join_button.setText('Join again')
        self.password_edit.setFocus()

    def timerEvent(self, event) -> None:  # noqa: N802 (Qt override)
        while not self.log_queue.empty():
            self.log_view.appendPlainText(self.log_queue.get_nowait())

    def start_join(self) -> None:
        username = self.username_edit.text().strip()
        password = self.password_edit.text()
        if not username or not password:
            QMessageBox.warning(self, 'Missing information', 'Please enter a username and password.')
            return

        self.join_button.setEnabled(False)
        self.log_view.clear()

        self.thread = QThread()
        self.worker = JoinWorker(
            username, password,
            self.domain_edit.text().strip(),
            self.dc_ip_edit.text().strip(),
            self.dc_fingerprint_edit.text().strip(),
            self.skip_login_manager_checkbox.isChecked(),
            self.force_ucs_dns_checkbox.isChecked(),
            self.mount_home_checkbox.isChecked(),
            self.admin_group_edit.text().strip(),
        )
        self.worker.moveToThread(self.thread)
        self.thread.started.connect(self.worker.run)
        self.worker.finished.connect(self.on_join_finished)
        self.worker.host_key_confirmation_requested.connect(self.confirm_host_key, Qt.BlockingQueuedConnection)
        self.thread.start()

    def confirm_host_key(self, dc_ip: str, fingerprints: List[str]) -> None:
        assert self.worker is not None
        answer = QMessageBox.question(
            self, 'Verify the domain controller',
            'The SSH host key of the domain controller %s is:\n\n%s\n\n'
            'Compare it with the output of `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` '
            'on the domain controller. Is this the right domain controller?' % (dc_ip, '\n'.join(fingerprints)),
        )
        self.worker.host_key_accepted = answer == QMessageBox.Yes

    def set_login_list_mode(self, index: int) -> None:
        try:
            login_users.set_mode(self.login_list_combo.itemData(index))
        except Exception as exc:
            debug_logger.exception('Changing the login screen user list failed')
            QMessageBox.critical(self, 'Login screen', str(exc))

    def edit_shares(self) -> None:
        try:
            available = shares.list_shares()
            configured = shares.configured_share_names()
            home_mounted = shares.home_mount_enabled()
        except Exception as exc:
            debug_logger.exception('Listing shares failed')
            QMessageBox.critical(self, 'Network shares', 'Could not read the shares from UCS: %s' % (exc,))
            return
        dialog = SharesDialog(self, available, configured, home_mounted)
        if not dialog.exec_():
            return
        try:
            shares.setup_shares(dialog.selected())
        except Exception as exc:
            debug_logger.exception('Share setup failed')
            QMessageBox.critical(self, 'Network shares', str(exc))
        else:
            QMessageBox.information(self, 'Network shares', 'Saved. Shares are mounted at the next login.')

    def on_join_finished(self, success: bool, error_message: str) -> None:
        self.join_button.setEnabled(True)
        if self.thread is not None:
            self.thread.quit()
            self.thread.wait()
        if success:
            self.show_join_state()
            self.shares_button.setEnabled(True)
            self.login_list_combo.setEnabled(True)
            QMessageBox.information(self, 'Success', 'Domain join successful. Please reboot this machine.')
        else:
            QMessageBox.critical(self, 'Domain join failed', '%s\n\nDetails: %s' % (error_message, LOGFILE))


def main() -> None:
    set_up_file_logging()
    app = QApplication(sys.argv)
    # Lets Wayland compositors match the window to its .desktop entry/icon.
    app.setDesktopFileName('univention-arch-connector')
    dialog = DomainJoinDialog()
    dialog.exec_()
    sys.exit(0)


if __name__ == '__main__':
    main()
