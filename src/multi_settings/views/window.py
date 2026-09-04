from __future__ import annotations

import gi

gi.require_version("Adw", "1")
gi.require_version("Gtk", "4.0")

from gi.repository import Adw, Gdk, Gtk

from multi_settings.config import APP_NAME
from multi_settings.views.hardening import HardeningPage
from multi_settings.views.overview import OverviewPage
from multi_settings.views.users import UsersPage
from multi_settings.views.yubikeys import YubiKeysPage


class MainWindow(Adw.ApplicationWindow):
    def __init__(self, application: Adw.Application) -> None:
        super().__init__(application=application, title=APP_NAME)
        self.set_default_size(1_120, 760)
        self.set_size_request(780, 560)
        self._install_styles()

        self.toast_overlay = Adw.ToastOverlay()
        content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        header = Adw.HeaderBar()
        header.set_title_widget(Gtk.Label(label=APP_NAME, css_classes=["heading"]))
        content.append(header)

        main = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, hexpand=True, vexpand=True)
        self.stack = Gtk.Stack(
            transition_type=Gtk.StackTransitionType.CROSSFADE,
            hexpand=True,
            vexpand=True,
        )
        sidebar = Gtk.StackSidebar(stack=self.stack)
        sidebar.set_size_request(210, -1)
        sidebar.add_css_class("navigation-sidebar")
        main.append(sidebar)
        main.append(Gtk.Separator(orientation=Gtk.Orientation.VERTICAL))
        scroller = Gtk.ScrolledWindow(hexpand=True, vexpand=True)
        scroller.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        scroller.set_child(self.stack)
        main.append(scroller)
        content.append(main)
        self.toast_overlay.set_child(content)
        self.set_content(self.toast_overlay)

        self._add_page(OverviewPage(), "overview", "Overview", "computer-symbolic")
        self._add_page(UsersPage(self.notify), "users", "Users", "system-users-symbolic")
        self._add_page(YubiKeysPage(self.notify), "yubikeys", "YubiKeys", "dialog-password-symbolic")
        self._add_page(HardeningPage(self.notify, self), "hardening", "Hardening", "security-high-symbolic")

    def _add_page(self, page: Gtk.Widget, name: str, title: str, icon: str) -> None:
        child = self.stack.add_titled(page, name, title)
        child.set_icon_name(icon)

    def notify(self, message: str) -> None:
        self.toast_overlay.add_toast(Adw.Toast.new(message))

    @staticmethod
    def _install_styles() -> None:
        provider = Gtk.CssProvider()
        provider.load_from_data(
            b"""
            .card { background: alpha(@card_bg_color, 0.96); border-radius: 12px; padding: 8px; }
            .success { color: #2ec27e; font-weight: 600; }
            .warning { color: #e5a50a; font-weight: 600; }
            .error { color: #e01b24; font-weight: 600; }
            .accent { color: @accent_color; font-weight: 600; }
            """
        )
        display = Gdk.Display.get_default()
        if display is not None:
            Gtk.StyleContext.add_provider_for_display(
                display, provider, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION
            )
