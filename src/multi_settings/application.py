from __future__ import annotations

from pathlib import Path

import gi

gi.require_version("Adw", "1")
gi.require_version("Gtk", "4.0")

from gi.repository import Adw, Gio, GLib

from multi_settings.config import APP_ID
from multi_settings.services.desktop_shortcut import DesktopShortcutService
from multi_settings.views.window import MainWindow


class MultiSettingsApplication(Adw.Application):
    def __init__(self) -> None:
        super().__init__(application_id=APP_ID, flags=Gio.ApplicationFlags.DEFAULT_FLAGS)

    def do_activate(self) -> None:
        self._ensure_desktop_shortcut()
        window = self.props.active_window
        if window is None:
            window = MainWindow(self)
        window.present()

    @staticmethod
    def _ensure_desktop_shortcut() -> None:
        desktop = GLib.get_user_special_dir(GLib.UserDirectory.DIRECTORY_DESKTOP)
        if not desktop:
            return
        service = DesktopShortcutService(Path(desktop))
        try:
            shortcut = service.ensure()
            if shortcut is not None:
                Gio.File.new_for_path(str(shortcut)).set_attribute_string(
                    "metadata::trusted",
                    "true",
                    Gio.FileQueryInfoFlags.NONE,
                    None,
                )
        except (OSError, GLib.Error):
            # A desktop icon is a convenience and must never prevent startup.
            try:
                service.marker.unlink(missing_ok=True)
            except OSError:
                pass
            return
