from __future__ import annotations

import shutil

import gi

gi.require_version("Gtk", "4.0")

from gi.repository import Gtk

from multi_settings.config import HELPER_PATH
from multi_settings.i18n import _
from multi_settings.views.common import section


class OverviewPage(Gtk.Box):
    def __init__(self) -> None:
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=28)
        self.set_margin_top(32)
        self.set_margin_bottom(32)
        self.set_margin_start(32)
        self.set_margin_end(32)
        privilege, body = section(_("Overview"))
        helper_ready = HELPER_PATH.is_file()
        policy_ready = shutil.which("pkexec") is not None
        for name, ready in (
            (_("Installed privileged helper"), helper_ready),
            (_("PolicyKit client"), policy_ready),
            (_("YubiKey Manager"), shutil.which("ykman") is not None),
            (_("PAM U2F enrollment"), shutil.which("pamu2fcfg") is not None),
            ("Ansible", shutil.which("ansible-playbook") is not None),
        ):
            row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
            row.set_margin_top(10)
            row.set_margin_bottom(10)
            row.set_margin_start(12)
            row.set_margin_end(12)
            row.append(Gtk.Label(label=name, xalign=0, hexpand=True))
            status = Gtk.Label(label=_("Ready") if ready else _("Not found"))
            status.add_css_class("success" if ready else "warning")
            row.append(status)
            body.append(row)
        self.append(privilege)

        workflow, workflow_body = section(_("Order of execution"))
        for number, text in enumerate(
            (
                _("Load custom-settings.yaml, run an audit, review the results, and apply hardening."),
                _("Create and verify the administrator and standard accounts."),
                _("Enroll primary and secondary YubiKeys, then enable login and sudo requirements."),
            ),
            start=1,
        ):
            label = Gtk.Label(label=f"{number}.  {text}", xalign=0, wrap=True)
            label.set_margin_top(8)
            label.set_margin_bottom(8)
            label.set_margin_start(12)
            label.set_margin_end(12)
            workflow_body.append(label)
        self.append(workflow)
