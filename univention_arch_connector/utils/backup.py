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
from shutil import copy2
from typing import List, Optional, TypedDict

from univention_arch_connector.utils.general import execute_as_root

userinfo_logger = logging.getLogger('userinfo')

BACKUP_ROOT = Path('/var/univention-arch-connector-backup')


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

    def __init__(self, backup_dir: Path) -> None:
        self.backup_dir = backup_dir
        self.manifest: List[ManifestEntry] = []

    @staticmethod
    def _create_impl() -> "Backup":
        timestamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
        backup_dir = BACKUP_ROOT / timestamp
        backup_dir.mkdir(parents=True, exist_ok=False)
        userinfo_logger.info('Backing up changed configuration files to %s', backup_dir)
        return Backup(backup_dir)

    @staticmethod
    @execute_as_root
    def create() -> "Backup":
        return Backup._create_impl()

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
        userinfo_logger.info('Wrote backup manifest to %s', manifest_path)


def find_latest_backup_dir() -> Optional[Path]:
    if not BACKUP_ROOT.is_dir():
        return None
    candidates = sorted((d for d in BACKUP_ROOT.iterdir() if d.is_dir()), reverse=True)
    return candidates[0] if candidates else None


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
