from __future__ import annotations

import gi

gi.require_version("Gtk", "4.0")

from gi.repository import Gtk


def page_title(title: str, subtitle: str) -> Gtk.Box:
    box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
    title_label = Gtk.Label(label=title, xalign=0)
    title_label.add_css_class("title-1")
    subtitle_label = Gtk.Label(label=subtitle, xalign=0, wrap=True)
    subtitle_label.add_css_class("dim-label")
    box.append(title_label)
    box.append(subtitle_label)
    return box


def section(title: str, description: str = "") -> tuple[Gtk.Box, Gtk.Box]:
    outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
    heading = Gtk.Label(label=title, xalign=0)
    heading.add_css_class("title-3")
    outer.append(heading)
    if description:
        detail = Gtk.Label(label=description, xalign=0, wrap=True)
        detail.add_css_class("dim-label")
        outer.append(detail)
    body = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
    body.add_css_class("card")
    outer.append(body)
    return outer, body


def form_row(label: str, control: Gtk.Widget) -> Gtk.Box:
    row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=18)
    row.set_margin_top(8)
    row.set_margin_bottom(8)
    row.set_margin_start(12)
    row.set_margin_end(12)
    text = Gtk.Label(label=label, xalign=0, hexpand=True)
    text.set_mnemonic_widget(control)
    row.append(text)
    row.append(control)
    return row


def clear_box(box: Gtk.Box | Gtk.ListBox) -> None:
    child = box.get_first_child()
    while child is not None:
        following = child.get_next_sibling()
        box.remove(child)
        child = following
