from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

import gi

gi.require_version("Adw", "1")
gi.require_version("GLib", "2.0")
gi.require_version("Gtk", "4.0")

from gi.repository import Adw, GLib, Gtk, Pango

from multi_settings.config import HARDENING_COLLECTION_VERSION, STATE_FILE
from multi_settings.domain.models import HardeningResult, TaskStatus
from multi_settings.domain.validation import ValidationError
from multi_settings.i18n import _
from multi_settings.services.hardening import HardeningService, parse_task_event
from multi_settings.services.hardening_results import HardeningResultsExporter
from multi_settings.services.privileged import PrivilegedResponse
from multi_settings.services.settings import CustomSettingsService
from multi_settings.views.common import clear_box, form_row, page_title, section


class ResultRow(Gtk.ListBoxRow):
    def __init__(self, result: HardeningResult) -> None:
        super().__init__()
        self.result = result
        content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
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
        role = result.role.rsplit(".", maxsplit=1)[-1] if result.role else _("playbook")
        role_label = Gtk.Label(label=role, xalign=0, width_chars=18)
        role_label.add_css_class("dim-label")
        status_labels = {
            TaskStatus.SUCCESS: _("Success"),
            TaskStatus.SKIPPED: _("Skipped"),
            TaskStatus.FAILED: _("Failed"),
        }
        status = Gtk.Label(label=status_labels[result.status], xalign=0, width_chars=9)
        status.add_css_class(
            "success" if result.status is TaskStatus.SUCCESS else "error" if result.status is TaskStatus.FAILED else "dim-label"
        )
        changed = Gtk.Label(label=_("Changed") if result.changed else "—", xalign=0, width_chars=8)
        row.append(task)
        row.append(role_label)
        row.append(status)
        row.append(changed)
        content.append(row)
        if result.status in (TaskStatus.SKIPPED, TaskStatus.FAILED):
            detail = Gtk.Label(
                label=_("Reason: {details}").format(details=result.details),
                xalign=0,
                wrap=True,
                selectable=True,
                css_classes=["dim-label"],
            )
            detail.set_margin_start(12)
            detail.set_margin_end(12)
            detail.set_margin_bottom(8)
            content.append(detail)
        self.set_child(content)


class HardeningPage(Gtk.Box):
    def __init__(self, notify, parent_window: Gtk.Window) -> None:
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=28)
        self.notify = notify
        self.parent_window = parent_window
        self.settings_service = CustomSettingsService()
        self.hardening_service = HardeningService()
        self.results_exporter = HardeningResultsExporter()
        self.variables: dict[str, Any] = {}
        self.results: list[HardeningResult] = []
        self.sort_key = "task"
        self.sort_reverse = False
        self.running = False
        self.last_run_audit = True
        self.last_os_hardening = True
        self.last_ssh_hardening = True
        self.backup_id: str | None = None
        self.pulse_source: int | None = None
        self.set_margin_top(32)
        self.set_margin_bottom(32)
        self.set_margin_start(32)
        self.set_margin_end(32)
        self.append(page_title(_("Hardening")))

        collection, collection_body = section(_("Pinned collection"))
        collection_label = Gtk.Label(
            label=_("DevSec Hardening {version} is bundled with the package and reused without a runtime download.").format(
                version=HARDENING_COLLECTION_VERSION
            ),
            xalign=0,
            wrap=True,
        )
        collection_label.set_margin_top(12)
        collection_label.set_margin_bottom(12)
        collection_label.set_margin_start(12)
        collection_label.set_margin_end(12)
        collection_body.append(collection_label)
        self.append(collection)

        settings, settings_body = section(
            _("Custom settings"),
            _("Settings are loaded from the package and then ~/.config/multi-settings/custom-settings.yaml. Your settings take precedence."),
        )
        settings_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        settings_row.set_margin_top(12)
        settings_row.set_margin_bottom(12)
        settings_row.set_margin_start(12)
        settings_row.set_margin_end(12)
        self.settings_label = Gtk.Label(label=_("No custom settings imported"), xalign=0, hexpand=True)
        settings_row.append(self.settings_label)
        choose = Gtk.Button(label=_("Import custom-settings.yaml"))
        choose.connect("clicked", self._choose_settings)
        settings_row.append(choose)
        settings_body.append(settings_row)
        self.append(settings)

        components, components_body = section(
            _("Hardening components"),
            _("Select OS hardening, SSH hardening, or both."),
        )
        self.os_hardening_switch = Gtk.Switch(active=True, valign=Gtk.Align.CENTER)
        self.ssh_hardening_switch = Gtk.Switch(active=True, valign=Gtk.Align.CENTER)
        components_body.append(form_row(_("OS hardening"), self.os_hardening_switch))
        components_body.append(form_row(_("SSH hardening"), self.ssh_hardening_switch))
        self.append(components)

        run, run_body = section(
            _("Current audit status"),
            _("Audit uses Ansible check mode. Apply makes local changes and can change SSH access."),
        )
        controls = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        controls.set_margin_top(12)
        controls.set_margin_start(12)
        controls.set_margin_end(12)
        self.audit_button = Gtk.Button(label=_("Run audit"))
        self.audit_button.connect("clicked", lambda _button: self._run(audit=True))
        self.apply_button = Gtk.Button(label=_("Apply hardening"))
        self.apply_button.add_css_class("suggested-action")
        self.apply_button.connect("clicked", self._confirm_apply)
        controls.append(self.audit_button)
        controls.append(self.apply_button)
        self.download_button = Gtk.Button(label=_("Download results"), sensitive=False)
        self.download_button.connect("clicked", self._download_results)
        controls.append(self.download_button)
        self.summary = Gtk.Label(label=_("Not audited"), xalign=1, hexpand=True)
        self.summary.add_css_class("dim-label")
        run_body.append(controls)
        self.summary.set_margin_start(12)
        self.summary.set_margin_end(12)
        run_body.append(self.summary)
        self.progress = Gtk.ProgressBar(show_text=True, text=_("Ready"))
        self.progress.set_margin_top(12)
        self.progress.set_margin_bottom(12)
        self.progress.set_margin_start(12)
        self.progress.set_margin_end(12)
        run_body.append(self.progress)
        self.append(run)

        recovery, recovery_body = section(
            _("Recovery backup"),
            _("A root-only configuration backup is created immediately before each apply. Reverting restores files and metadata changed by that run; installed packages are retained."),
        )
        recovery_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        recovery_row.set_margin_top(12)
        recovery_row.set_margin_bottom(12)
        recovery_row.set_margin_start(12)
        recovery_row.set_margin_end(12)
        self.backup_label = Gtk.Label(
            label=_("No hardening backup is available."),
            xalign=0,
            hexpand=True,
            wrap=True,
        )
        recovery_row.append(self.backup_label)
        self.restore_button = Gtk.Button(label=_("Revert from backup"), sensitive=False)
        self.restore_button.add_css_class("destructive-action")
        self.restore_button.connect("clicked", self._confirm_restore)
        recovery_row.append(self.restore_button)
        recovery_body.append(recovery_row)
        self.append(recovery)

        results_section, results_body = section(
            _("Task results"),
            _("Select a column heading to sort. Select it again to reverse the order."),
        )
        header = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        header.set_margin_start(12)
        header.set_margin_end(12)
        for title, key, width, expand in (
            (_("Task"), "task", 0, True),
            (_("Role"), "role", 18, False),
            (_("Status"), "status", 9, False),
            (_("Changed"), "changed", 8, False),
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
        self._load_backup_state()

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
            (_("{count} top-level override loaded") if count == 1 else _("{count} top-level overrides loaded")).format(count=count)
            if count else _("No custom settings imported")
        )

    def _choose_settings(self, _button: Gtk.Button) -> None:
        chooser = Gtk.FileChooserNative.new(
            _("Import custom-settings.yaml"),
            self.parent_window,
            Gtk.FileChooserAction.OPEN,
            _("Import"),
            _("Cancel"),
        )
        yaml_filter = Gtk.FileFilter()
        yaml_filter.set_name(_("YAML settings"))
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
            self.notify(_("Choose a local YAML file."))
            return
        try:
            self.variables = self.settings_service.import_file(Path(path))
        except ValidationError as error:
            self.notify(str(error))
            return
        self._update_settings_label()
        self.notify(_("Imported custom settings. They will override package and role defaults."))

    def _run(self, *, audit: bool) -> None:
        if self.running:
            return
        os_hardening = self.os_hardening_switch.get_active()
        ssh_hardening = self.ssh_hardening_switch.get_active()
        if not os_hardening and not ssh_hardening:
            self.notify(_("Select OS hardening, SSH hardening, or both."))
            return
        try:
            self.variables = self.settings_service.load()
        except ValidationError as error:
            self.notify(str(error))
            return
        self._update_settings_label()
        self.running = True
        self.last_run_audit = audit
        self.last_os_hardening = os_hardening
        self.last_ssh_hardening = ssh_hardening
        self.results.clear()
        clear_box(self.result_list)
        self.audit_button.set_sensitive(False)
        self.apply_button.set_sensitive(False)
        self.download_button.set_sensitive(False)
        self.restore_button.set_sensitive(False)
        self.os_hardening_switch.set_sensitive(False)
        self.ssh_hardening_switch.set_sensitive(False)
        self.progress.set_fraction(0)
        self.progress.set_text(_("Auditing…") if audit else _("Applying hardening…"))
        self.summary.set_label(_("Running"))
        self.pulse_source = GLib.timeout_add(180, self._pulse)
        self.hardening_service.run_async(
            audit=audit,
            variables=self.variables,
            os_hardening=os_hardening,
            ssh_hardening=ssh_hardening,
            event_callback=lambda event: GLib.idle_add(self._handle_event, event),
            callback=lambda response: GLib.idle_add(self._finished, response, audit),
        )

    def _confirm_apply(self, _button: Gtk.Button) -> None:
        if not self._selected_component_names():
            self.notify(_("Select OS hardening, SSH hardening, or both."))
            return
        dialog = Adw.AlertDialog(
            heading=_("Apply hardening?"),
            body=self._apply_warning(),
        )
        dialog.add_response("cancel", _("Cancel"))
        dialog.add_response("apply", _("Apply hardening"))
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
            self.progress.set_text(_("Processed {count} tasks").format(count=len(self.results)))
        elif event.get("event") == "task_start":
            task = str(event.get("task", _("Working")))
            self.progress.set_text(task[:90])
        elif event.get("event") == "backup_created":
            backup_id = event.get("backup_id")
            if isinstance(backup_id, str):
                self.backup_id = backup_id
                self.backup_label.set_label(
                    _("Creating backup {backup_id}…").format(backup_id=backup_id)
                )
        return GLib.SOURCE_REMOVE

    def _finished(self, response: PrivilegedResponse, audit: bool) -> bool:
        self.running = False
        if self.pulse_source is not None:
            GLib.source_remove(self.pulse_source)
            self.pulse_source = None
        if not response.ok and not any(
            result.status is TaskStatus.FAILED for result in self.results
        ):
            failure = HardeningResult(
                task=_("Hardening operation"),
                role="",
                status=TaskStatus.FAILED,
                changed=False,
                details=response.message,
            )
            self.results.append(failure)
            self.result_list.append(ResultRow(failure))
        self.audit_button.set_sensitive(True)
        self.apply_button.set_sensitive(True)
        self.download_button.set_sensitive(bool(self.results))
        self.os_hardening_switch.set_sensitive(True)
        self.ssh_hardening_switch.set_sensitive(True)
        self._load_backup_state()
        self.progress.set_fraction(1 if response.ok else 0)
        self.progress.set_text(_("Complete") if response.ok else _("Failed"))
        counts = {status: 0 for status in TaskStatus}
        for result in self.results:
            counts[result.status] += 1
        summary = _("{success} success · {skipped} skipped · {failed} failed").format(
            success=counts[TaskStatus.SUCCESS],
            skipped=counts[TaskStatus.SKIPPED],
            failed=counts[TaskStatus.FAILED],
        )
        if audit:
            summary += _(" · {count} need changes").format(
                count=sum(result.changed for result in self.results)
            )
        self.summary.set_label(summary)
        self.notify(response.message)
        return GLib.SOURCE_REMOVE

    def _load_backup_state(self) -> None:
        try:
            state = json.loads(STATE_FILE.read_text(encoding="utf-8"))
            backup = state.get("hardening_backup")
        except (OSError, json.JSONDecodeError):
            backup = None
        if not isinstance(backup, dict) or not isinstance(backup.get("id"), str):
            self.backup_id = None
            self.backup_label.set_label(_("No hardening backup is available."))
            self.restore_button.set_sensitive(False)
            return
        self.backup_id = backup["id"]
        status = backup.get("status")
        created_at = str(backup.get("created_at", ""))
        components = backup.get("components", [])
        component_labels = {
            "os_hardening": _("OS hardening"),
            "ssh_hardening": _("SSH hardening"),
        }
        selected = ", ".join(
            component_labels[item] for item in components if item in component_labels
        )
        if status == "available":
            self.backup_label.set_label(
                _("Backup {backup_id} is ready ({components}, {created_at}).").format(
                    backup_id=self.backup_id,
                    components=selected,
                    created_at=created_at,
                )
            )
            self.restore_button.set_sensitive(not self.running)
        elif status == "restored":
            self.backup_label.set_label(
                _("Backup {backup_id} has been restored.").format(
                    backup_id=self.backup_id
                )
            )
            self.restore_button.set_sensitive(False)
        else:
            self.backup_label.set_label(
                _("Backup {backup_id} is being prepared.").format(
                    backup_id=self.backup_id
                )
            )
            self.restore_button.set_sensitive(False)

    def _confirm_restore(self, _button: Gtk.Button) -> None:
        if self.backup_id is None or self.running:
            return
        dialog = Adw.AlertDialog(
            heading=_("Revert hardening from backup?"),
            body=_("This restores configuration files and metadata changed by the last hardening run. Later edits to those files will be overwritten. Packages installed by hardening are retained."),
        )
        dialog.add_response("cancel", _("Cancel"))
        dialog.add_response("restore", _("Revert hardening"))
        dialog.set_response_appearance("restore", Adw.ResponseAppearance.DESTRUCTIVE)
        dialog.set_default_response("cancel")
        dialog.set_close_response("cancel")
        dialog.choose(self.parent_window, None, self._restore_confirmed)

    def _restore_confirmed(self, dialog: Adw.AlertDialog, result) -> None:
        if dialog.choose_finish(result) != "restore" or self.backup_id is None:
            return
        self.running = True
        self.audit_button.set_sensitive(False)
        self.apply_button.set_sensitive(False)
        self.restore_button.set_sensitive(False)
        self.os_hardening_switch.set_sensitive(False)
        self.ssh_hardening_switch.set_sensitive(False)
        self.progress.set_fraction(0)
        self.progress.set_text(_("Reverting hardening…"))
        self.summary.set_label(_("Running"))
        self.pulse_source = GLib.timeout_add(180, self._pulse)
        self.hardening_service.restore_async(
            self.backup_id,
            lambda response: GLib.idle_add(self._restore_finished, response),
        )

    def _restore_finished(self, response: PrivilegedResponse) -> bool:
        self.running = False
        if self.pulse_source is not None:
            GLib.source_remove(self.pulse_source)
            self.pulse_source = None
        self.audit_button.set_sensitive(True)
        self.apply_button.set_sensitive(True)
        self.download_button.set_sensitive(bool(self.results))
        self.os_hardening_switch.set_sensitive(True)
        self.ssh_hardening_switch.set_sensitive(True)
        self.progress.set_fraction(1 if response.ok else 0)
        self.progress.set_text(_("Reverted") if response.ok else _("Failed"))
        self.summary.set_label(
            _("Hardening configuration was reverted from backup.")
            if response.ok
            else _("The backup could not be restored.")
        )
        self._load_backup_state()
        self.notify(response.message)
        return GLib.SOURCE_REMOVE

    def _apply_warning(self) -> str:
        components = self._selected_component_names()
        warning = _("This changes the local machine. Selected components: {components}.").format(
            components=", ".join(components)
        )
        warning += " " + _("A configuration backup will be created before changes begin.")
        if self.ssh_hardening_switch.get_active():
            warning += " " + _("SSH hardening can change remote access. Review the audit and ensure you retain a working access path.")
        return warning

    def _selected_component_names(self) -> list[str]:
        selected: list[str] = []
        if self.os_hardening_switch.get_active():
            selected.append(_("OS hardening"))
        if self.ssh_hardening_switch.get_active():
            selected.append(_("SSH hardening"))
        return selected

    def _download_results(self, _button: Gtk.Button) -> None:
        chooser = Gtk.FileChooserNative.new(
            _("Download hardening results"),
            self.parent_window,
            Gtk.FileChooserAction.SAVE,
            _("Save"),
            _("Cancel"),
        )
        chooser.set_current_name(
            f"multi-settings-hardening-{datetime.now().strftime('%Y%m%d-%H%M%S')}.csv"
        )
        csv_filter = Gtk.FileFilter()
        csv_filter.set_name(_("CSV results"))
        csv_filter.add_pattern("*.csv")
        chooser.add_filter(csv_filter)
        chooser.connect("response", self._results_destination_chosen)
        chooser.show()

    def _results_destination_chosen(
        self, chooser: Gtk.FileChooserNative, response: int
    ) -> None:
        if response != Gtk.ResponseType.ACCEPT:
            return
        selected = chooser.get_file()
        path = selected.get_path() if selected is not None else None
        if path is None:
            self.notify(_("Choose a local destination."))
            return
        try:
            saved_path = self.results_exporter.save(
                Path(path),
                self.results,
                audit=self.last_run_audit,
                os_hardening=self.last_os_hardening,
                ssh_hardening=self.last_ssh_hardening,
            )
        except (OSError, ValueError) as error:
            self.notify(_("Could not save hardening results: {error}").format(error=error))
            return
        self.notify(_("Saved hardening results to {path}.").format(path=saved_path))

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
