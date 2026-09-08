from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from multi_settings.privileged.hardening_backup import (
    create_hardening_backup,
    finalize_hardening_backup,
    restore_hardening_backup,
)


class HardeningBackupTests(unittest.TestCase):
    def test_restore_reverts_only_paths_changed_during_hardening(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "etc"
            source.mkdir()
            original = source / "existing.conf"
            original.write_text("before\n", encoding="utf-8")
            unchanged = source / "unchanged.conf"
            unchanged.write_text("same\n", encoding="utf-8")
            deleted = source / "deleted.conf"
            deleted.write_text("restore me\n", encoding="utf-8")
            backup_root = root / "backups"
            state: dict = {"version": 1, "enrollments": [], "pam": {}}

            with (
                patch(
                    "multi_settings.privileged.hardening_backup.HARDENING_BACKUP_DIR",
                    backup_root,
                ),
                patch(
                    "multi_settings.privileged.hardening_backup.OS_BACKUP_SOURCES",
                    (source,),
                ),
                patch(
                    "multi_settings.privileged.hardening_backup.load_state",
                    side_effect=lambda: state,
                ),
                patch(
                    "multi_settings.privileged.hardening_backup.save_state",
                    side_effect=lambda updated: state.update(updated),
                ),
                patch("multi_settings.privileged.hardening_backup.subprocess.run"),
                patch("multi_settings.privileged.hardening_backup.emit"),
            ):
                backup_id = create_hardening_backup(("os_hardening",))
                original.write_text("hardened\n", encoding="utf-8")
                deleted.unlink()
                added = source / "new-hardening.conf"
                added.write_text("new\n", encoding="utf-8")
                finalize_hardening_backup(backup_id)

                self.assertEqual(backup_root.stat().st_mode & 0o777, 0o700)
                self.assertEqual(
                    (backup_root / backup_id / "manifest.json").stat().st_mode
                    & 0o777,
                    0o600,
                )

                # A later edit to a path not touched by the hardening run is
                # deliberately preserved by the targeted restore.
                unchanged.write_text("later\n", encoding="utf-8")
                restore_hardening_backup({"backup_id": backup_id})

            self.assertEqual(original.read_text(encoding="utf-8"), "before\n")
            self.assertFalse(added.exists())
            self.assertEqual(deleted.read_text(encoding="utf-8"), "restore me\n")
            self.assertEqual(unchanged.read_text(encoding="utf-8"), "later\n")
            self.assertEqual(state["hardening_backup"]["status"], "restored")


if __name__ == "__main__":
    unittest.main()
