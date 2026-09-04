from __future__ import annotations

import json
import threading

import gi

gi.require_version("GLib", "2.0")
gi.require_version("Gtk", "4.0")

from gi.repository import GLib, Gtk

from multi_settings.config import STATE_FILE
from multi_settings.domain.models import KeySlot
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
        self.set_margin_top(32)
        self.set_margin_bottom(32)
        self.set_margin_start(32)
        self.set_margin_end(32)
        self.append(
            page_title(
                "YubiKeys",
                "Enroll two distinct FIDO credentials per account and require them as a second factor.",
            )
        )

        detected, detected_body = section(
            "Connected keys",
            "Serial-number discovery does not request administrator authentication. Touch the selected key during enrollment.",
        )
        selectors = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        self.account = Gtk.ComboBoxText(hexpand=True)
        self.slot = Gtk.ComboBoxText()
        self.slot.append(KeySlot.PRIMARY.value, "Primary")
        self.slot.append(KeySlot.SECONDARY.value, "Secondary")
        self.slot.set_active_id(KeySlot.PRIMARY.value)
        refresh = Gtk.Button(icon_name="view-refresh-symbolic", tooltip_text="Refresh connected keys")
        refresh.connect("clicked", lambda _button: self.refresh())
        selectors.append(self.account)
        selectors.append(self.slot)
        selectors.append(refresh)
        detected_body.append(form_row("Enroll for account and slot", selectors))
        self.connected_list = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        detected_body.append(self.connected_list)
        self.append(detected)

        enrolled, self.enrolled_list = section("Enrolled keys")
        self.append(enrolled)

        policy, policy_body = section(
            "Password + YubiKey requirement",
            "Enabling is refused until every affected account has a key. The setting is added only to each selected PAM service.",
        )
        self.login_switch = Gtk.Switch(valign=Gtk.Align.CENTER)
        self.sudo_switch = Gtk.Switch(valign=Gtk.Align.CENTER)
        policy_body.append(form_row("Graphical and console login", self.login_switch))
        policy_body.append(form_row("sudo and sudo -i", self.sudo_switch))
        self.save_policy = Gtk.Button(label="Save requirements", halign=Gtk.Align.END)
        self.save_policy.add_css_class("suggested-action")
        self.save_policy.connect("clicked", self._save_requirements)
        policy_body.append(self.save_policy)
        self.append(policy)
        self.refresh()
        GLib.timeout_add_seconds(2, self._poll_connected)

    def refresh(self) -> None:
        selected = self.account.get_active_id()
        self.account.remove_all()
        for user in SystemUserService.list_interactive_users():
            label = f"{user.username} ({'administrator' if user.is_administrator else 'standard'})"
            self.account.append(user.username, label)
        if selected is not None:
            self.account.set_active_id(selected)
        if self.account.get_active() < 0:
            self.account.set_active(0)
        self._poll_connected()
        self._refresh_enrolled()
        self._load_policy_state()

    def _poll_connected(self) -> bool:
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
            message = Gtk.Label(label="No YubiKey detected, or ykman is unavailable.", xalign=0)
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
            labels.append(Gtk.Label(label=key.status, xalign=0, css_classes=["dim-label"]))
            row.append(labels)
            button = Gtk.Button(label="Enrolled" if key.enrollment else "Enroll")
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
            label = Gtk.Label(label="No keys enrolled.", xalign=0)
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
                label=f"{enrollment.username} · {enrollment.slot.value.title()} · {enrollment.serial}",
                xalign=0,
                hexpand=True,
            )
            row.append(text)
            remove = Gtk.Button(label="Un-enroll")
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
        username = self.account.get_active_id()
        slot_name = self.slot.get_active_id()
        if username is None or slot_name is None:
            self.notify("Choose an account and slot.")
            return
        self.notify("Touch the YubiKey when it flashes.")
        self.service.enroll_async(
            username,
            serial,
            KeySlot(slot_name),
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
