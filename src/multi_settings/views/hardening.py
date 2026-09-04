from __future__ import annotations

from pathlib import Path
from typing import Any

import gi

gi.require_version("Adw", "1")
gi.require_version("GLib", "2.0")
gi.require_version("Gtk", "4.0")

from gi.repository import Adw, GLib, Gtk, Pango

from multi_settings.domain.models import HardeningResult, TaskStatus
from multi_settings.domain.validation import ValidationError
from multi_settings.services.hardening import HardeningService, parse_task_event
from multi_settings.services.privileged import PrivilegedResponse
from multi_settings.services.settings import CustomSettingsService
from multi_settings.views.common import clear_box, page_title, section


class ResultRow(Gtk.ListBoxRow):
    def __init__(self, result: HardeningResult) -> None:
        super().__init__()
        self.result = result
        row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        row.set_margin_top(8)
        row.set_margin_bottom(8)
        row.set_margin_start(12)
        row.set_margin_end(12)
        task = Gtk.Label(
            label=result.task,
            xalign=0,
            hexpand=True,
            ellipsize=Pango.EllipsizeMode.END,
        )
        task.set_tooltip_text(result.details or result.task)
        role = result.role.rsplit(".", maxsplit=1)[-1] if result.role else "playbook"
        role_label = Gtk.Label(label=role, xalign=0, width_chars=18)
        role_label.add_css_class("dim-label")
        status = Gtk.Label(label=result.status.value.title(), xalign=0, width_chars=9)
        status.add_css_class(
            "success" if result.status is TaskStatus.SUCCESS else "error" if result.status is TaskStatus.FAILED else "dim-label"
        )
        changed = Gtk.Label(label="Changed" if result.changed else "—", xalign=0, width_chars=8)
        row.append(task)
        row.append(role_label)
        row.append(status)
        row.append(changed)
        self.set_child(row)


class HardeningPage(Gtk.Box):
    def __init__(self, notify, parent_window: Gtk.Window) -> None:
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=28)
        self.notify = notify
        self.parent_window = parent_window
        self.settings_service = CustomSettingsService()
        self.hardening_service = HardeningService()
        self.variables: dict[str, Any] = {}
        self.results: list[HardeningResult] = []
        self.sort_key = "task"
        self.sort_reverse = False
        self.running = False
        self.pulse_source: int | None = None
        self.set_margin_top(32)
        self.set_margin_bottom(32)
        self.set_margin_start(32)
        self.set_margin_end(32)
        self.append(
            page_title(
                "OS and SSH hardening",
                "Audit or apply devsec.hardening for Ubuntu 26.04. Imported values override role defaults in both runs.",
            )
        )

        settings, settings_body = section(
            "Custom settings",
            "Import a YAML mapping of DevSec role variables. The file is validated and copied into your private configuration directory without sudo.",
        )
        settings_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        settings_row.set_margin_top(12)
        settings_row.set_margin_bottom(12)
        settings_row.set_margin_start(12)
        settings_row.set_margin_end(12)
        self.settings_label = Gtk.Label(label="No custom settings imported", xalign=0, hexpand=True)
        settings_row.append(self.settings_label)
        choose = Gtk.Button(label="Import custom-settings.yml")
        choose.connect("clicked", self._choose_settings)
        settings_row.append(choose)
        settings_body.append(settings_row)
        self.append(settings)

        run, run_body = section(
            "Current audit status",
            "Audit uses Ansible check mode. Apply makes local changes and can change SSH access.",
        )
        controls = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        controls.set_margin_top(12)
        controls.set_margin_start(12)
        controls.set_margin_end(12)
        self.audit_button = Gtk.Button(label="Run audit")
        self.audit_button.connect("clicked", lambda _button: self._run(audit=True))
        self.apply_button = Gtk.Button(label="Apply hardening")
        self.apply_button.add_css_class("suggested-action")
        self.apply_button.connect("clicked", self._confirm_apply)
        controls.append(self.audit_button)
        controls.append(self.apply_button)
        self.summary = Gtk.Label(label="Not audited", xalign=1, hexpand=True)
        self.summary.add_css_class("dim-label")
        controls.append(self.summary)
        run_body.append(controls)
        self.progress = Gtk.ProgressBar(show_text=True, text="Ready")
        self.progress.set_margin_top(12)
        self.progress.set_margin_bottom(12)
        self.progress.set_margin_start(12)
        self.progress.set_margin_end(12)
        run_body.append(self.progress)
        self.append(run)

        results_section, results_body = section(
            "Task results",
            "Select a column heading to sort. Select it again to reverse the order.",
        )
        header = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        header.set_margin_start(12)
        header.set_margin_end(12)
        for title, key, width, expand in (
            ("Task", "task", 0, True),
            ("Role", "role", 18, False),
            ("Status", "status", 9, False),
            ("Changed", "changed", 8, False),
        ):
            button = Gtk.Button(label=title, has_frame=False, hexpand=expand, halign=Gtk.Align.FILL)
            if width:
                button.set_size_request(width * 8, -1)
            button.connect("clicked", self._change_sort, key)
            header.append(button)
        results_body.append(header)
        separator = Gtk.Separator()
        results_body.append(separator)
        self.result_list = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE)
        self.result_list.set_sort_func(self._sort_rows)
        results_body.append(self.result_list)
        self.append(results_section)
        self._load_saved_settings()

    def _load_saved_settings(self) -> None:
        try:
            self.variables = self.settings_service.load()
        except ValidationError as error:
            self.notify(str(error))
            self.variables = {}
        self._update_settings_label()

    def _update_settings_label(self) -> None:
        count = len(self.variables)
        self.settings_label.set_label(
            f"{count} top-level override{'s' if count != 1 else ''} loaded"
            if count
            else "No custom settings imported"
        )

    def _choose_settings(self, _button: Gtk.Button) -> None:
        chooser = Gtk.FileChooserNative.new(
            "Import custom-settings.yml",
            self.parent_window,
            Gtk.FileChooserAction.OPEN,
            "Import",
            "Cancel",
        )
        yaml_filter = Gtk.FileFilter()
        yaml_filter.set_name("YAML settings")
        yaml_filter.add_pattern("*.yml")
        yaml_filter.add_pattern("*.yaml")
        chooser.add_filter(yaml_filter)
        chooser.connect("response", self._settings_chosen)
        chooser.show()

    def _settings_chosen(self, chooser: Gtk.FileChooserNative, response: int) -> None:
        if response != Gtk.ResponseType.ACCEPT:
            return
        selected = chooser.get_file()
        path = selected.get_path() if selected is not None else None
        if path is None:
            self.notify("Choose a local YAML file.")
            return
        try:
            self.variables = self.settings_service.import_file(Path(path))
        except ValidationError as error:
            self.notify(str(error))
            return
        self._update_settings_label()
        self.notify("Imported custom settings. They will override role defaults.")

    def _run(self, *, audit: bool) -> None:
        if self.running:
            return
        self.running = True
        self.results.clear()
        clear_box(self.result_list)
        self.audit_button.set_sensitive(False)
        self.apply_button.set_sensitive(False)
        self.progress.set_fraction(0)
        self.progress.set_text("Auditing…" if audit else "Applying hardening…")
        self.summary.set_label("Running")
        self.pulse_source = GLib.timeout_add(180, self._pulse)
        self.hardening_service.run_async(
            audit=audit,
            variables=self.variables,
            event_callback=lambda event: GLib.idle_add(self._handle_event, event),
            callback=lambda response: GLib.idle_add(self._finished, response, audit),
        )

    def _confirm_apply(self, _button: Gtk.Button) -> None:
        dialog = Adw.AlertDialog(
            heading="Apply OS and SSH hardening?",
            body=(
                "This changes the local machine. DevSec SSH defaults can disable password login, "
                "root login, and forwarding. Review the audit and ensure you retain a working access path."
            ),
        )
        dialog.add_response("cancel", "Cancel")
        dialog.add_response("apply", "Apply hardening")
        dialog.set_response_appearance("apply", Adw.ResponseAppearance.DESTRUCTIVE)
        dialog.set_default_response("cancel")
        dialog.set_close_response("cancel")
        dialog.choose(self.parent_window, None, self._apply_confirmed)

    def _apply_confirmed(self, dialog: Adw.AlertDialog, result) -> None:
        if dialog.choose_finish(result) == "apply":
            self._run(audit=False)

    def _pulse(self) -> bool:
        if not self.running:
            return GLib.SOURCE_REMOVE
        self.progress.pulse()
        return GLib.SOURCE_CONTINUE

    def _handle_event(self, event: dict[str, Any]) -> bool:
        result = parse_task_event(event)
        if result is not None:
            self.results.append(result)
            self.result_list.append(ResultRow(result))
            self.progress.set_text(f"Processed {len(self.results)} tasks")
        elif event.get("event") == "task_start":
            task = str(event.get("task", "Working"))
            self.progress.set_text(task[:90])
        return GLib.SOURCE_REMOVE

    def _finished(self, response: PrivilegedResponse, audit: bool) -> bool:
        self.running = False
        if self.pulse_source is not None:
            GLib.source_remove(self.pulse_source)
            self.pulse_source = None
        self.audit_button.set_sensitive(True)
        self.apply_button.set_sensitive(True)
        self.progress.set_fraction(1 if response.ok else 0)
        self.progress.set_text("Complete" if response.ok else "Failed")
        counts = {status: 0 for status in TaskStatus}
        for result in self.results:
            counts[result.status] += 1
        self.summary.set_label(
            f"{counts[TaskStatus.SUCCESS]} success · "
            f"{counts[TaskStatus.SKIPPED]} skipped · {counts[TaskStatus.FAILED]} failed"
            + (
                f" · {sum(result.changed for result in self.results)} need changes"
                if audit
                else ""
            )
        )
        self.notify(response.message)
        return GLib.SOURCE_REMOVE

    def _change_sort(self, _button: Gtk.Button, key: str) -> None:
        if self.sort_key == key:
            self.sort_reverse = not self.sort_reverse
        else:
            self.sort_key = key
            self.sort_reverse = False
        self.result_list.invalidate_sort()

    def _sort_rows(self, first: ResultRow, second: ResultRow) -> int:
        left: Any = getattr(first.result, self.sort_key)
        right: Any = getattr(second.result, self.sort_key)
        if isinstance(left, TaskStatus):
            left = left.value
            right = right.value
        comparison = (left > right) - (left < right)
        return -comparison if self.sort_reverse else comparison
