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


def test_restore_file_deletes_created_new_dangling_symlink(tmp_path):
    target = tmp_path / 'CAcert.pem'
    link = tmp_path / 'UCSdomain.crt'
    link.symlink_to(target)  # target already removed, e.g. by an earlier entry
    entry = {
        'original_path': str(link),
        'backup_relpath': None,
        'action': 'created-new',
        'sha256_before': None,
    }

    backup_mod._restore_file_impl(entry, tmp_path)

    assert not link.is_symlink()


def test_find_latest_backup_dir_picks_most_recent(tmp_path, monkeypatch):
    monkeypatch.setattr(backup_mod, 'BACKUP_ROOT', tmp_path)
    for name in ('20250101T000000Z', '20250601T000000Z', '20250301T000000Z'):
        _make_backup(tmp_path, name)

    latest = backup_mod.find_latest_backup_dir()
    assert latest.name == '20250601T000000Z'


def test_backup_dir_without_manifest_is_skipped(tmp_path, monkeypatch):
    monkeypatch.setattr(backup_mod, 'BACKUP_ROOT', tmp_path)
    usable = _make_backup(tmp_path, '20250101T000000Z')
    (tmp_path / '20250102T000000Z').mkdir()  # join aborted before writing the manifest

    assert backup_mod.find_latest_backup_dir() == usable


def test_find_latest_backup_dir_none_when_root_missing(tmp_path, monkeypatch):
    monkeypatch.setattr(backup_mod, 'BACKUP_ROOT', tmp_path / 'does-not-exist')
    assert backup_mod.find_latest_backup_dir() is None


def _make_backup(root, name, joined_before=None, sssd_conf_action=None):
    """A backup dir with a meta file (joined_before set) or, like backups
    from before meta files existed, only a manifest.
    """
    backup_dir = root / name
    backup_dir.mkdir(parents=True)
    manifest = []
    if sssd_conf_action is not None:
        manifest.append({
            'original_path': backup_mod.SSSD_CONF_PATH,
            'backup_relpath': None,
            'action': sssd_conf_action,
            'sha256_before': None,
        })
    (backup_dir / 'manifest.json').write_text(json.dumps(manifest))
    if joined_before is not None:
        (backup_dir / backup_mod.META_FILE).write_text(json.dumps({'joined_before': joined_before}))
    return backup_dir


def test_leave_skips_backups_taken_by_a_rejoin(tmp_path, monkeypatch):
    monkeypatch.setattr(backup_mod, 'BACKUP_ROOT', tmp_path)
    _make_backup(tmp_path, '20250101T000000Z', joined_before=False)
    pre_join = _make_backup(tmp_path, '20250102T000000Z', joined_before=False)
    _make_backup(tmp_path, '20250103T000000Z', joined_before=True)
    _make_backup(tmp_path, '20250104T000000Z', joined_before=True)

    assert backup_mod.find_latest_backup_dir() == pre_join


def test_legacy_backup_with_existing_sssd_conf_counts_as_rejoin(tmp_path, monkeypatch):
    monkeypatch.setattr(backup_mod, 'BACKUP_ROOT', tmp_path)
    pre_join = _make_backup(tmp_path, '20250101T000000Z', sssd_conf_action='created-new')
    _make_backup(tmp_path, '20250102T000000Z', sssd_conf_action='modified')

    assert backup_mod.find_latest_backup_dir() == pre_join


def test_prune_keeps_the_leave_backup_and_newer(tmp_path, monkeypatch):
    monkeypatch.setattr(backup_mod, 'BACKUP_ROOT', tmp_path)
    old = _make_backup(tmp_path, '20250101T000000Z', joined_before=False)
    old_rejoin = _make_backup(tmp_path, '20250102T000000Z', joined_before=True)
    pre_join = _make_backup(tmp_path, '20250103T000000Z', joined_before=False)
    rejoin = _make_backup(tmp_path, '20250104T000000Z', joined_before=True)

    backup_mod._prune_old_backups_impl()

    assert not old.exists() and not old_rejoin.exists()
    assert pre_join.exists() and rejoin.exists()


def test_backup_dirs_are_private(tmp_path, monkeypatch):
    root = tmp_path / 'backups'
    monkeypatch.setattr(backup_mod, 'BACKUP_ROOT', root)

    b = Backup._create_impl(joined_before=True)
    b.write_manifest()

    assert root.stat().st_mode & 0o777 == 0o700
    assert b.backup_dir.stat().st_mode & 0o777 == 0o700
    assert json.loads((b.backup_dir / backup_mod.META_FILE).read_text()) == {'joined_before': True}
