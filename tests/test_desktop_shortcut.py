from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from multi_settings.services.desktop_shortcut import DesktopShortcutService


class DesktopShortcutTests(unittest.TestCase):
    def test_shortcut_is_created_once_for_one_user(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "application.desktop"
            source.write_text("[Desktop Entry]\nExec=multi-settings\n", encoding="utf-8")
            marker = root / "config" / "desktop-icon-created"
            installer_uid = root / "installer-uid"
            installer_uid.write_text(f"{os.getuid()}\n", encoding="ascii")
            service = DesktopShortcutService(
                root / "Desktop",
                source=source,
                marker=marker,
                installer_uid_file=installer_uid,
            )

            shortcut = service.ensure()

            self.assertIsNotNone(shortcut)
            self.assertEqual(shortcut.read_text(encoding="utf-8"), source.read_text(encoding="utf-8"))
            self.assertEqual(shortcut.stat().st_mode & 0o777, 0o755)
            self.assertEqual(marker.stat().st_mode & 0o777, 0o600)
            self.assertIsNone(service.ensure())

    def test_existing_different_shortcut_is_not_overwritten(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "application.desktop"
            source.write_text("trusted source", encoding="utf-8")
            desktop = root / "Desktop"
            desktop.mkdir()
            existing = desktop / "Multi Settings.desktop"
            existing.write_text("user content", encoding="utf-8")
            installer_uid = root / "installer-uid"
            installer_uid.write_text(f"{os.getuid()}\n", encoding="ascii")
            service = DesktopShortcutService(
                desktop,
                source=source,
                marker=root / "config" / "desktop-icon-created",
                installer_uid_file=installer_uid,
            )

            self.assertIsNone(service.ensure())
            self.assertEqual(existing.read_text(encoding="utf-8"), "user content")

    def test_non_installer_does_not_receive_a_shortcut(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "application.desktop"
            source.write_text("trusted source", encoding="utf-8")
            installer_uid = root / "installer-uid"
            installer_uid.write_text(f"{os.getuid() + 1}\n", encoding="ascii")
            service = DesktopShortcutService(
                root / "Desktop",
                source=source,
                marker=root / "config" / "desktop-icon-created",
                installer_uid_file=installer_uid,
            )

            self.assertIsNone(service.ensure())
            self.assertFalse((root / "Desktop").exists())


if __name__ == "__main__":
    unittest.main()
