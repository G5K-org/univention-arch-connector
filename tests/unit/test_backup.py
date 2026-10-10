# SPDX-FileCopyrightText: 2025 univention-arch-connector contributors
# SPDX-License-Identifier: AGPL-3.0-only

import json

from univention_arch_connector.utils import backup as backup_mod
from univention_arch_connector.utils.backup import Backup


def test_backup_file_records_modified_entry_and_copies_content(tmp_path):
    backup_dir = tmp_path / 'backup'
    backup_dir.mkdir()
    b = Backup(backup_dir)

    original = tmp_path / 'etc' / 'foo.conf'
    original.parent.mkdir(parents=True)
    original.write_text('old content\n')

    b.backup_file(str(original))

    assert len(b.manifest) == 1
    entry = b.manifest[0]
    assert entry['original_path'] == str(original)
    assert entry['action'] == 'modified'
    assert entry['sha256_before'] is not None
    assert (backup_dir / entry['backup_relpath']).read_text() == 'old content\n'


def test_backup_file_records_created_new_entry_when_absent(tmp_path):
    backup_dir = tmp_path / 'backup'
    backup_dir.mkdir()
    b = Backup(backup_dir)

    missing = tmp_path / 'etc' / 'does-not-exist.conf'

    b.backup_file(str(missing))

    entry = b.manifest[0]
    assert entry['action'] == 'created-new'
    assert entry['backup_relpath'] is None


def test_write_manifest_round_trips_through_load_manifest(tmp_path, monkeypatch):
    backup_dir = tmp_path / 'backup'
    backup_dir.mkdir()
    b = Backup(backup_dir)

    original = tmp_path / 'etc' / 'foo.conf'
    original.parent.mkdir(parents=True)
    original.write_text('hello\n')
    b.backup_file(str(original))
    b.write_manifest()

    loaded = backup_mod.load_manifest(backup_dir)
    assert loaded == b.manifest
    assert json.loads((backup_dir / 'manifest.json').read_text()) == b.manifest


def test_restore_file_restores_modified_file(tmp_path):
    backup_dir = tmp_path / 'backup'
    backup_dir.mkdir()
    b = Backup(backup_dir)

    original = tmp_path / 'etc' / 'foo.conf'
    original.parent.mkdir(parents=True)
    original.write_text('original content\n')
    b.backup_file(str(original))

    original.write_text('modified by join\n')
    assert original.read_text() == 'modified by join\n'

    backup_mod._restore_file_impl(b.manifest[0], backup_dir)
    assert original.read_text() == 'original content\n'


def test_restore_file_deletes_created_new_file(tmp_path):
    backup_dir = tmp_path / 'backup'
    backup_dir.mkdir()
    b = Backup(backup_dir)

    created = tmp_path / 'etc' / 'new-by-join.conf'
    b.backup_file(str(created))  # records as created-new, since it doesn't exist yet

    created.parent.mkdir(parents=True, exist_ok=True)
    created.write_text('written during join\n')
    assert created.exists()

    backup_mod._restore_file_impl(b.manifest[0], backup_dir)
    assert not created.exists()


def test_find_latest_backup_dir_picks_most_recent(tmp_path, monkeypatch):
    monkeypatch.setattr(backup_mod, 'BACKUP_ROOT', tmp_path)
    (tmp_path / '20250101T000000Z').mkdir()
    (tmp_path / '20250601T000000Z').mkdir()
    (tmp_path / '20250301T000000Z').mkdir()

    latest = backup_mod.find_latest_backup_dir()
    assert latest.name == '20250601T000000Z'


def test_find_latest_backup_dir_none_when_root_missing(tmp_path, monkeypatch):
    monkeypatch.setattr(backup_mod, 'BACKUP_ROOT', tmp_path / 'does-not-exist')
    assert backup_mod.find_latest_backup_dir() is None
