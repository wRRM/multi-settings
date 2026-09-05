from __future__ import annotations

import gi

gi.require_version("GLib", "2.0")
gi.require_version("Gtk", "4.0")

from gi.repository import GLib, Gtk

from multi_settings.domain.validation import ValidationError, validate_full_name, validate_password, validate_username
from multi_settings.i18n import _
from multi_settings.services.privileged import PrivilegedClient, PrivilegedResponse
from multi_settings.services.system_users import SystemUserService
from multi_settings.views.common import clear_box, form_row, page_title, section


class UsersPage(Gtk.Box):
    def __init__(self, notify) -> None:
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=28)
        self.notify = notify
        self.privileged = PrivilegedClient()
        self.set_margin_top(32)
        self.set_margin_bottom(32)
        self.set_margin_start(32)
        self.set_margin_end(32)
        self.append(page_title(_("Users"), _("Create Ubuntu accounts without running the application as root.")))

        existing, self.user_list = section(_("Interactive accounts"))
        self.append(existing)

        create, form = section(
            _("Create account"),
            _("The account password is sent only to the local root helper over its private standard input."),
        )
        self.username = Gtk.Entry(placeholder_text=_("username"), width_chars=28)
        self.full_name = Gtk.Entry(placeholder_text=_("Full name"), width_chars=28)
        self.password = Gtk.PasswordEntry(show_peek_icon=True, width_chars=28)
        self.confirm = Gtk.PasswordEntry(show_peek_icon=True, width_chars=28)
        self.administrator = Gtk.Switch(valign=Gtk.Align.CENTER)
        form.append(form_row(_("Username"), self.username))
        form.append(form_row(_("Full name"), self.full_name))
        form.append(form_row(_("Password"), self.password))
        form.append(form_row(_("Confirm password"), self.confirm))
        form.append(form_row(_("Administrator (sudo group)"), self.administrator))
        self.create_button = Gtk.Button(label=_("Create account"), halign=Gtk.Align.END)
        self.create_button.add_css_class("suggested-action")
        self.create_button.set_margin_top(8)
        self.create_button.connect("clicked", self._create_user)
        form.append(self.create_button)
        self.append(create)
        self.refresh()

    def refresh(self) -> None:
        clear_box(self.user_list)
        users = SystemUserService.list_interactive_users()
        if not users:
            self.user_list.append(Gtk.Label(label=_("No interactive accounts found."), xalign=0))
            return
        for user in users:
            row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
            row.set_margin_top(10)
            row.set_margin_bottom(10)
            row.set_margin_start(12)
            row.set_margin_end(12)
            names = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2, hexpand=True)
            name = Gtk.Label(label=user.full_name or user.username, xalign=0)
            name.add_css_class("heading")
            names.append(name)
            detail = Gtk.Label(label=f"{user.username} · UID {user.uid}", xalign=0)
            detail.add_css_class("dim-label")
            names.append(detail)
            row.append(names)
            badge = Gtk.Label(label=_("Administrator") if user.is_administrator else _("Standard"))
            badge.add_css_class("accent" if user.is_administrator else "dim-label")
            row.append(badge)
            self.user_list.append(row)

    def _create_user(self, _button: Gtk.Button) -> None:
        try:
            username = validate_username(self.username.get_text())
            full_name = validate_full_name(self.full_name.get_text())
            password = validate_password(self.password.get_text())
            if password != self.confirm.get_text():
                raise ValidationError(_("The passwords do not match."))
        except ValidationError as error:
            self.notify(str(error))
            return
        payload = {
            "username": username,
            "full_name": full_name,
            "password": password,
            "administrator": self.administrator.get_active(),
        }
        self.password.set_text("")
        self.confirm.set_text("")
        self.create_button.set_sensitive(False)
        self.privileged.run_async(
            "user.create", payload, lambda response: GLib.idle_add(self._created, response)
        )

    def _created(self, response: PrivilegedResponse) -> bool:
        self.create_button.set_sensitive(True)
        self.notify(response.message)
        if response.ok:
            self.username.set_text("")
            self.full_name.set_text("")
            self.administrator.set_active(False)
            self.refresh()
        return GLib.SOURCE_REMOVE
