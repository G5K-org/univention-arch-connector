#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2025 univention-arch-connector contributors
# SPDX-License-Identifier: AGPL-3.0-only
#
# New module (no upstream equivalent). Upstream copies a fixed, hardcoded
# list of files into a per-run backup directory and has no concept of
# restoring them again. This module generalizes that into a manifest so the
# (new, Arch-only) --leave-domain path can programmatically undo a join.
# See ../../NOTICE.md.

import hashlib
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from shutil import copy2, rmtree
from typing import List, Optional, Tuple, TypedDict

from univention_arch_connector.utils.general import execute_as_root

userinfo_logger = logging.getLogger('userinfo')

BACKUP_ROOT = Path('/var/univention-arch-connector-backup')
# Written next to manifest.json.
META_FILE = 'meta.json'
SSSD_CONF_PATH = '/etc/sssd/sssd.conf'


class ManifestEntry(TypedDict):
    original_path: str
    backup_relpath: Optional[str]  # None if action == "created-new"
    action: str  # "modified" | "created-new"
    sha256_before: Optional[str]


class Backup:
    """Collects a manifest of every config file a join step is about to
    change, copying pre-images into a timestamped directory so a later
    ``--leave-domain`` run (or a human) can review/restore them.
    """

    def __init__(self, backup_dir: Path, joined_before: bool = False) -> None:
        self.backup_dir = backup_dir
        self.manifest: List[ManifestEntry] = []
        # Whether this system was already joined when the backup was taken
        # (a re-join). Such a backup holds domain configuration, so
        # --leave-domain must not restore from it.
        self.joined_before = joined_before

    @staticmethod
    def _create_impl(joined_before: bool) -> "Backup":
        timestamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
        # Backups contain machine secrets: keep them private to root.
        BACKUP_ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
        BACKUP_ROOT.chmod(0o700)
        backup_dir = BACKUP_ROOT / timestamp
        backup_dir.mkdir(mode=0o700, exist_ok=False)
        userinfo_logger.info('Backing up changed configuration files to %s', backup_dir)
        return Backup(backup_dir, joined_before)

    @staticmethod
    @execute_as_root
    def create(joined_before: bool = False) -> "Backup":
        return Backup._create_impl(joined_before)

    def backup_file(self, path: str) -> None:
        """Record that ``path`` is about to be changed, copying its current
        contents into the backup directory if it already exists. Not
        decorated with execute_as_root: every call site is already inside
        a configurator's decorated backup() method, which has already
        restored root for the duration of the call.
        """
        p = Path(path)
        if p.exists():
            relpath = str(p).lstrip('/')
            dest = self.backup_dir / relpath
            dest.parent.mkdir(parents=True, exist_ok=True)
            copy2(p, dest)
            sha256_before = hashlib.sha256(p.read_bytes()).hexdigest()
            entry: ManifestEntry = {
                'original_path': str(p),
                'backup_relpath': relpath,
                'action': 'modified',
                'sha256_before': sha256_before,
            }
        else:
            entry = {
                'original_path': str(p),
                'backup_relpath': None,
                'action': 'created-new',
                'sha256_before': None,
            }
        self.manifest.append(entry)

    def write_manifest(self) -> None:
        # Not decorated - see the note on backup_file() above.
        manifest_path = self.backup_dir / 'manifest.json'
        manifest_path.write_text(json.dumps(self.manifest, indent=2))
        (self.backup_dir / META_FILE).write_text(json.dumps({'joined_before': self.joined_before}, indent=2))
        userinfo_logger.info('Wrote backup manifest to %s', manifest_path)


def _backup_dirs_newest_first() -> List[Path]:
    if not BACKUP_ROOT.is_dir():
        return []
    return sorted((d for d in BACKUP_ROOT.iterdir() if d.is_dir()), reverse=True)


def _taken_before_join(backup_dir: Path) -> bool:
    try:
        return not json.loads((backup_dir / META_FILE).read_text())['joined_before']
    except FileNotFoundError:
        pass
    # Older backups have no meta file: an sssd.conf that already existed
    # when the backup was taken means the system was joined.
    try:
        manifest = load_manifest(backup_dir)
    except (OSError, ValueError):
        return False
    return not any(
        entry['original_path'] == SSSD_CONF_PATH and entry['action'] == 'modified' for entry in manifest
    )


def find_latest_backup_dir() -> Optional[Path]:
    """The backup --leave-domain restores: the newest one taken while the
    system was not joined yet. Backups taken by later re-joins hold domain
    configuration and are skipped.
    """
    for backup_dir in _backup_dirs_newest_first():
        if _taken_before_join(backup_dir):
            return backup_dir
    return None


def entries_for_leave(backup_dir: Path) -> List[Tuple[ManifestEntry, Path]]:
    """Manifest entries to restore when leaving, each with the backup dir
    holding its copy: those of ``backup_dir``, plus files that only later
    backups (taken by re-joins, possibly by a newer version of this tool)
    recorded. For every file, the oldest recorded state wins - for a file a
    re-join touched for the first time, that is its state before joining.
    """
    entries: List[Tuple[ManifestEntry, Path]] = []
    seen = set()
    for candidate in reversed(_backup_dirs_newest_first()):
        if candidate < backup_dir:
            continue
        try:
            manifest = load_manifest(candidate)
        except (OSError, ValueError):
            continue
        for entry in manifest:
            if entry['original_path'] not in seen:
                seen.add(entry['original_path'])
                entries.append((entry, candidate))
    return entries


def _prune_old_backups_impl() -> None:
    leave_backup = find_latest_backup_dir()
    if leave_backup is None:
        return
    for backup_dir in _backup_dirs_newest_first():
        if backup_dir < leave_backup:
            rmtree(backup_dir)
            userinfo_logger.info('Removed obsolete backup %s', backup_dir)


@execute_as_root
def prune_old_backups() -> None:
    """Delete backups older than the one --leave-domain would use. They
    belong to earlier join cycles and only keep old machine secrets around.
    """
    _prune_old_backups_impl()


def load_manifest(backup_dir: Path) -> List[ManifestEntry]:
    manifest_path = backup_dir / 'manifest.json'
    return json.loads(manifest_path.read_text())


def _restore_file_impl(entry: ManifestEntry, backup_dir: Path) -> None:
    original_path = Path(entry['original_path'])
    if entry['action'] == 'created-new':
        # is_symlink(): also remove links whose target was already removed.
        if original_path.exists() or original_path.is_symlink():
            original_path.unlink()
            userinfo_logger.info('Removed %s (was created by join)', original_path)
    else:
        backup_relpath = entry['backup_relpath']
        assert backup_relpath is not None
        src = backup_dir / backup_relpath
        if src.exists():
            original_path.parent.mkdir(parents=True, exist_ok=True)
            copy2(src, original_path)
            userinfo_logger.info('Restored %s from backup', original_path)
        else:
            userinfo_logger.warning('Backup copy for %s not found at %s, skipping', original_path, src)


@execute_as_root
def restore_file(entry: ManifestEntry, backup_dir: Path) -> None:
    """Restore a single manifest entry: delete files that were newly
    created by the join, or copy the pre-image back for files that were
    modified in place.
    """
    _restore_file_impl(entry, backup_dir)
