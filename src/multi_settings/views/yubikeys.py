from __future__ import annotations

import json
import threading

import gi

gi.require_version("GLib", "2.0")
gi.require_version("Gtk", "4.0")

from gi.repository import GLib, Gtk

from multi_settings.config import STATE_FILE
from multi_settings.domain.models import KeySlot
from multi_settings.i18n import _
from multi_settings.services.privileged import PrivilegedClient, PrivilegedResponse
from multi_settings.services.system_users import SystemUserService
from multi_settings.services.yubikeys import YubiKeyService
from multi_settings.views.common import clear_box, form_row, page_title, section


class YubiKeysPage(Gtk.Box):
    def __init__(self, notify) -> None:
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=28)
        self.notify = notify
        self.privileged = PrivilegedClient()
        self.service = YubiKeyService(self.privileged)
        self.polling = False
        self.stopped = False
        self.poll_source: int | None = None
        self.selected_username: str | None = None
        self.rebuilding_accounts = False
        self.set_margin_top(32)
        self.set_margin_bottom(32)
        self.set_margin_start(32)
        self.set_margin_end(32)
        self.append(
            page_title(
                "YubiKeys",
                _("Enroll two distinct FIDO credentials per account and require them as a second factor."),
            )
        )

        detected, detected_body = section(
            _("Connected keys"),
            _("Serial-number discovery does not request administrator authentication. Touch the selected key during enrollment."),
        )
        selectors = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        self.account = Gtk.ComboBoxText(hexpand=True)
        self.account.connect("changed", self._account_changed)
        self.slot = Gtk.ComboBoxText()
        self.slot.append(KeySlot.PRIMARY.value, _("Primary"))
        self.slot.append(KeySlot.SECONDARY.value, _("Secondary"))
        self.slot.set_active_id(KeySlot.PRIMARY.value)
        refresh = Gtk.Button(icon_name="view-refresh-symbolic", tooltip_text=_("Refresh connected keys"))
        refresh.connect("clicked", lambda _button: self.refresh())
        selectors.append(self.account)
        selectors.append(self.slot)
        selectors.append(refresh)
        detected_body.append(form_row(_("Enroll for account and slot"), selectors))
        self.pin = Gtk.PasswordEntry(show_peek_icon=True, width_chars=18)
        detected_body.append(form_row(_("FIDO2 PIN (if set)"), self.pin))
        pin_note = Gtk.Label(
            label=_("The PIN is used only during enrollment and is never stored."),
            xalign=0,
            wrap=True,
            css_classes=["dim-label"],
        )
        pin_note.set_margin_start(12)
        pin_note.set_margin_end(12)
        detected_body.append(pin_note)
        self.connected_list = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        detected_body.append(self.connected_list)
        self.append(detected)

        enrolled, self.enrolled_list = section(_("Enrolled keys"))
        self.append(enrolled)

        policy, policy_body = section(
            _("Password + YubiKey requirement"),
            _("Enabling is refused until every affected account has a key. The setting is added only to each selected PAM service."),
        )
        self.login_switch = Gtk.Switch(valign=Gtk.Align.CENTER)
        self.sudo_switch = Gtk.Switch(valign=Gtk.Align.CENTER)
        policy_body.append(form_row(_("Graphical and console login"), self.login_switch))
        policy_body.append(form_row(_("sudo and sudo -i"), self.sudo_switch))
        self.save_policy = Gtk.Button(label=_("Save requirements"), halign=Gtk.Align.END)
        self.save_policy.add_css_class("suggested-action")
        self.save_policy.connect("clicked", self._save_requirements)
        policy_body.append(self.save_policy)
        self.append(policy)
        self.refresh()
        self.poll_source = GLib.timeout_add_seconds(2, self._poll_connected)

    def stop_polling(self) -> None:
        self.stopped = True
        if self.poll_source is not None:
            GLib.source_remove(self.poll_source)
            self.poll_source = None

    def refresh(self) -> None:
        self.refresh_accounts()
        self._poll_connected()
        self._refresh_enrolled()
        self._load_policy_state()

    def refresh_accounts(self, preferred_username: str | None = None) -> None:
        selected = preferred_username or self.selected_username
        self.rebuilding_accounts = True
        self.account.remove_all()
        for user in SystemUserService.list_interactive_users():
            role = _("administrator") if user.is_administrator else _("standard")
            label = f"{user.username} ({role})"
            self.account.append(user.username, label)
        restored = selected is not None and self.account.set_active_id(selected)
        if not restored:
            self.account.set_active(0)
        self.rebuilding_accounts = False
        self.selected_username = self.account.get_active_id()

    def _account_changed(self, account: Gtk.ComboBoxText) -> None:
        if not self.rebuilding_accounts:
            self.selected_username = account.get_active_id()

    def _poll_connected(self) -> bool:
        if self.stopped:
            return GLib.SOURCE_REMOVE
        if self.polling:
            return GLib.SOURCE_CONTINUE
        self.polling = True

        def discover() -> None:
            keys = self.service.connected_keys()
            GLib.idle_add(self._render_connected, keys)

        threading.Thread(target=discover, daemon=True).start()
        return GLib.SOURCE_CONTINUE

    def _render_connected(self, keys) -> bool:
        self.polling = False
        clear_box(self.connected_list)
        if not keys:
            message = Gtk.Label(label=_("No YubiKey detected, or ykman is unavailable."), xalign=0)
            message.set_margin_top(12)
            message.set_margin_bottom(12)
            message.set_margin_start(12)
            self.connected_list.append(message)
            return GLib.SOURCE_REMOVE
        for key in keys:
            row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
            row.set_margin_top(8)
            row.set_margin_bottom(8)
            row.set_margin_start(12)
            row.set_margin_end(12)
            labels = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2, hexpand=True)
            serial = Gtk.Label(label=f"YubiKey {key.serial}", xalign=0)
            serial.add_css_class("heading")
            labels.append(serial)
            if key.enrollment is None:
                enrollment_status = _("Not enrolled")
            else:
                enrollment_status = _("{slot} for {username}").format(
                    slot=_(key.enrollment.slot.value.title()),
                    username=key.enrollment.username,
                )
            labels.append(Gtk.Label(label=enrollment_status, xalign=0, css_classes=["dim-label"]))
            row.append(labels)
            button = Gtk.Button(label=_("Enrolled") if key.enrollment else _("Enroll"))
            button.set_sensitive(key.enrollment is None)
            if key.enrollment is None:
                button.add_css_class("suggested-action")
                button.connect("clicked", self._enroll, key.serial)
            row.append(button)
            self.connected_list.append(row)
        return GLib.SOURCE_REMOVE

    def _refresh_enrolled(self) -> None:
        clear_box(self.enrolled_list)
        enrollments = self.service.enrollments()
        if not enrollments:
            label = Gtk.Label(label=_("No keys enrolled."), xalign=0)
            label.set_margin_top(12)
            label.set_margin_bottom(12)
            label.set_margin_start(12)
            self.enrolled_list.append(label)
            return
        for enrollment in enrollments:
            row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
            row.set_margin_top(8)
            row.set_margin_bottom(8)
            row.set_margin_start(12)
            row.set_margin_end(12)
            text = Gtk.Label(
                label=f"{enrollment.username} · {_(enrollment.slot.value.title())} · {enrollment.serial}",
                xalign=0,
                hexpand=True,
            )
            row.append(text)
            remove = Gtk.Button(label=_("Un-enroll"))
            remove.add_css_class("destructive-action")
            remove.connect("clicked", self._unenroll, enrollment.username, enrollment.slot)
            row.append(remove)
            self.enrolled_list.append(row)

    def _load_policy_state(self) -> None:
        try:
            state = json.loads(STATE_FILE.read_text(encoding="utf-8"))
            pam = state.get("pam", {})
        except (OSError, json.JSONDecodeError):
            pam = {}
        self.login_switch.set_active(pam.get("login") is True)
        self.sudo_switch.set_active(pam.get("sudo") is True)

    def _enroll(self, _button: Gtk.Button, serial: str) -> None:
        username = self.selected_username
        slot_name = self.slot.get_active_id()
        if username is None or slot_name is None:
            self.notify(_("Choose an account and slot."))
            return
        pin = self.pin.get_text()
        self.pin.set_text("")
        if len(pin.encode("utf-8")) > 63 or "\n" in pin or "\r" in pin or "\x00" in pin:
            self.notify(_("The FIDO2 PIN is invalid."))
            return
        self.notify(_("Touch the YubiKey when it flashes."))
        self.service.enroll_async(
            username,
            serial,
            KeySlot(slot_name),
            pin,
            lambda response: GLib.idle_add(self._operation_finished, response),
        )

    def _unenroll(self, _button: Gtk.Button, username: str, slot: KeySlot) -> None:
        self.service.unenroll_async(
            username,
            slot,
            lambda response: GLib.idle_add(self._operation_finished, response),
        )

    def _save_requirements(self, _button: Gtk.Button) -> None:
        self.save_policy.set_sensitive(False)
        self.privileged.run_async(
            "pam.configure",
            {"login": self.login_switch.get_active(), "sudo": self.sudo_switch.get_active()},
            lambda response: GLib.idle_add(self._requirements_saved, response),
        )

    def _requirements_saved(self, response: PrivilegedResponse) -> bool:
        self.save_policy.set_sensitive(True)
        self.notify(response.message)
        if not response.ok:
            self._load_policy_state()
        return GLib.SOURCE_REMOVE

    def _operation_finished(self, response: PrivilegedResponse) -> bool:
        self.notify(response.message)
        self.refresh()
        return GLib.SOURCE_REMOVE
