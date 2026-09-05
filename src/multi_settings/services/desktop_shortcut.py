from __future__ import annotations

import os
import tempfile
from pathlib import Path

from multi_settings.config import DESKTOP_FILE, INSTALLER_UID_FILE, user_config_dir


class DesktopShortcutService:
    """Creates one ordinary-user desktop shortcut after installation."""

    def __init__(
        self,
        desktop_directory: Path,
        *,
        source: Path = DESKTOP_FILE,
        marker: Path | None = None,
        installer_uid_file: Path = INSTALLER_UID_FILE,
    ) -> None:
        self.desktop_directory = desktop_directory
        self.source = source
        self.marker = marker or user_config_dir() / "onboarding-desktop-icon-created"
        self.installer_uid_file = installer_uid_file

    def ensure(self) -> Path | None:
        if not self._is_installer() or self.marker.exists() or not self.source.is_file():
            return None
        if self.desktop_directory == Path.home():
            return None
        self.desktop_directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        destination = self.desktop_directory / "Onboarding.desktop"
        source_content = self.source.read_text(encoding="utf-8")
        migrated = self._migrate_legacy_shortcut(destination, source_content)
        safe_to_trust = False
        if migrated:
            safe_to_trust = True
        elif not destination.exists():
            self._atomic_write(destination, source_content, 0o755)
            safe_to_trust = True
        elif not destination.is_symlink():
            safe_to_trust = destination.read_text(encoding="utf-8") == source_content
        self._atomic_write(self.marker, "created\n", 0o600)
        return destination if safe_to_trust else None

    def _migrate_legacy_shortcut(
        self, destination: Path, source_content: str
    ) -> bool:
        legacy = self.desktop_directory / "Multi Settings.desktop"
        if not legacy.is_file() or legacy.is_symlink():
            return False
        legacy_content = legacy.read_text(encoding="utf-8")
        migrated_content = legacy_content.replace(
            "Name=Multi Settings\n", "Name=Onboarding\n", 1
        )
        if migrated_content != source_content:
            return False
        if destination.exists():
            if destination.is_symlink():
                return False
            if destination.read_text(encoding="utf-8") != source_content:
                return False
        else:
            self._atomic_write(destination, source_content, 0o755)
        legacy.unlink()
        return True

    def _is_installer(self) -> bool:
        try:
            installer_uid = int(
                self.installer_uid_file.read_text(encoding="ascii").strip()
            )
        except (OSError, UnicodeError, ValueError):
            return False
        return installer_uid == os.getuid()

    @staticmethod
    def _atomic_write(destination: Path, content: str, mode: int) -> None:
        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{destination.name}.", dir=destination.parent, text=True
        )
        try:
            os.fchmod(descriptor, mode)
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary_name, destination)
        except BaseException:
            try:
                os.unlink(temporary_name)
            except FileNotFoundError:
                pass
            raise
