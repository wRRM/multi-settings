from __future__ import annotations

import gi

gi.require_version("Adw", "1")
gi.require_version("Gtk", "4.0")

from gi.repository import Adw, Gdk, Gtk

from multi_settings.config import APP_NAME
from multi_settings.i18n import _, get_language, set_language
from multi_settings.views.hardening import HardeningPage
from multi_settings.views.overview import OverviewPage
from multi_settings.views.users import UsersPage
from multi_settings.views.yubikeys import YubiKeysPage


class MainWindow(Adw.ApplicationWindow):
    def __init__(self, application: Adw.Application, visible_page: str = "overview") -> None:
        super().__init__(application=application, title=APP_NAME)
        self.set_default_size(1_120, 760)
        self.set_size_request(780, 560)
        self._install_styles()

        self.toast_overlay = Adw.ToastOverlay()
        content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        header = Adw.HeaderBar()
        header.set_title_widget(Gtk.Label(label=APP_NAME, css_classes=["heading"]))
        target_language = "en" if get_language() == "sv" else "sv"
        language_button = Gtk.Button(
            label="English" if target_language == "en" else "Svenska",
            tooltip_text=_("Switch to English") if target_language == "en" else _("Switch to Swedish"),
        )
        language_button.connect("clicked", self._switch_language, target_language)
        header.pack_end(language_button)
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

        self._add_page(OverviewPage(), "overview", _("Overview"), "computer-symbolic")
        self.hardening_page = HardeningPage(self.notify, self)
        self._add_page(self.hardening_page, "hardening", _("Hardening"), "security-high-symbolic")
        self.yubikeys_page = YubiKeysPage(self.notify)
        self.users_page = UsersPage(self.notify, self, self._accounts_changed)
        self._add_page(self.users_page, "users", _("Users"), "system-users-symbolic")
        self._add_page(self.yubikeys_page, "yubikeys", "YubiKeys", "dialog-password-symbolic")
        self.stack.set_visible_child_name(visible_page)

    def _add_page(self, page: Gtk.Widget, name: str, title: str, icon: str) -> None:
        child = self.stack.add_titled(page, name, title)
        child.set_icon_name(icon)

    def notify(self, message: str) -> None:
        self.toast_overlay.add_toast(Adw.Toast.new(message))

    def _accounts_changed(self, preferred_username: str | None) -> None:
        self.yubikeys_page.refresh_accounts(preferred_username)

    def _switch_language(self, _button: Gtk.Button, language: str) -> None:
        if self.hardening_page.running:
            self.notify(_("Wait for the hardening operation to finish before changing language."))
            return
        visible_page = self.stack.get_visible_child_name() or "overview"
        set_language(language, persist=True)
        replacement = MainWindow(self.get_application(), visible_page)
        replacement.present()
        self.close()

    def do_close_request(self) -> bool:
        self.yubikeys_page.stop_polling()
        return False

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
