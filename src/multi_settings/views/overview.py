from __future__ import annotations

import shutil

import gi

gi.require_version("Gtk", "4.0")

from gi.repository import Gtk

from multi_settings.config import HELPER_PATH
from multi_settings.views.common import page_title, section


class OverviewPage(Gtk.Box):
    def __init__(self) -> None:
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=28)
        self.set_margin_top(32)
        self.set_margin_bottom(32)
        self.set_margin_start(32)
        self.set_margin_end(32)
        self.append(
            page_title(
                "System preparation",
                "Create accounts, enroll two security keys, and audit Ubuntu 26.04 before applying OS and SSH hardening.",
            )
        )
        privilege, body = section(
            "Least-privilege design",
            "Discovery stays in this ordinary-user process. System changes use the desktop's administrator authentication window; one authorization is normally retained for five minutes.",
        )
        helper_ready = HELPER_PATH.is_file()
        policy_ready = shutil.which("pkexec") is not None
        for name, ready in (
            ("Installed privileged helper", helper_ready),
            ("PolicyKit client", policy_ready),
            ("YubiKey Manager", shutil.which("ykman") is not None),
            ("PAM U2F enrollment", shutil.which("pamu2fcfg") is not None),
            ("Ansible", shutil.which("ansible-playbook") is not None),
        ):
            row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
            row.set_margin_top(10)
            row.set_margin_bottom(10)
            row.set_margin_start(12)
            row.set_margin_end(12)
            row.append(Gtk.Label(label=name, xalign=0, hexpand=True))
            status = Gtk.Label(label="Ready" if ready else "Not found")
            status.add_css_class("success" if ready else "warning")
            row.append(status)
            body.append(row)
        self.append(privilege)

        workflow, workflow_body = section("Recommended order")
        for number, text in enumerate(
            (
                "Create and verify the administrator and standard accounts.",
                "Enroll primary and secondary YubiKeys, then enable login and sudo requirements.",
                "Import custom-settings.yml and run an audit.",
                "Review changed and failed tasks before applying hardening.",
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
