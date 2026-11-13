"""Shared GTK models and layout helpers."""

from gi.repository import GObject, Gtk


def box(*children, vertical=False, spacing=0, css=None):
    orientation = Gtk.Orientation.VERTICAL if vertical else Gtk.Orientation.HORIZONTAL
    widget = Gtk.Box(orientation=orientation, spacing=spacing)
    for child in children:
        widget.append(child)
    if css:
        widget.add_css_class(css)
    return widget


def label(text="", *classes):
    widget = Gtk.Label(label=text, xalign=0)
    for css_class in classes:
        widget.add_css_class(css_class)
    return widget


def endpoint_text(endpoint):
    return str(endpoint) if endpoint else "—"


class EventRow(GObject.Object):
    def __init__(self, event):
        super().__init__()
        self.event = event
        connection = event.connection.search_text if event.connection else ""
        self.search_text = (
            f"{event.kind} {event.detail} {event.source} {connection}".casefold()
        )
