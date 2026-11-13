"""GTK4 and Libadwaita interface for the socket explorer."""

import logging
from pathlib import Path
from threading import Thread

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gdk, Gio, GLib, GObject, Gtk, Pango

from . import APP_ID, VERSION
from .demo import collect_demo
from .network import collect

REFRESH_INTERVAL = 2
SCOPE_NAMES = ("All sockets", "TCP listeners", "Bound UDP")
PROTOCOL_NAMES = ("All protocols", "TCP", "UDP")
LOGGER = logging.getLogger(__name__)


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


class SocketRow(GObject.Object):
    def __init__(self, connection):
        super().__init__()
        self.connection = connection
        self.search_text = connection.search_text


class Explorer(Adw.ApplicationWindow):
    def __init__(self, application, demo):
        super().__init__(application=application, title="SocketForge")
        self.set_default_size(1120, 740)
        self.set_size_request(460, 440)
        self.demo = demo
        self.collect = collect_demo if demo else collect
        self.snapshot = None
        self.error = False
        self.paused = False
        self.in_flight = False
        self.discard_pending = False
        self.closed = False
        self.search_terms = ()

        self.store = Gio.ListStore.new(SocketRow)
        self.filter = Gtk.CustomFilter.new(self._matches)
        self.filtered = Gtk.FilterListModel.new(self.store, self.filter)
        self.filtered.connect("items-changed", self._update_table_status)

        self.toasts = Adw.ToastOverlay()
        toolbar = Adw.ToolbarView()
        toolbar.add_top_bar(self._header())
        toolbar.set_content(self._content())
        self.toasts.set_child(toolbar)
        self.set_content(self.toasts)
        self.connect("close-request", self._close)
        self.timer = GLib.timeout_add_seconds(REFRESH_INTERVAL, self._tick)
        self._refresh()

    def _header(self):
        header = Adw.HeaderBar()
        header.set_title_widget(
            Adw.WindowTitle(title="SocketForge", subtitle="Network Explorer")
        )

        menu = Gio.Menu()
        menu.append("Keyboard Shortcuts", "win.shortcuts")
        menu.append("About SocketForge", "win.about")
        header.pack_end(
            Gtk.MenuButton(
                icon_name="open-menu-symbolic",
                menu_model=menu,
                tooltip_text="Main Menu",
            )
        )

        self.pause_button = Gtk.Button()
        self._set_pause_button()
        self.pause_button.set_action_name("win.pause")
        header.pack_start(self.pause_button)
        refresh = Gtk.Button(
            icon_name="view-refresh-symbolic", tooltip_text="Refresh (Ctrl+R)"
        )
        refresh.set_action_name("win.refresh")
        header.pack_start(refresh)

        for name, handler, shortcut in (
            ("refresh", lambda *_: self._refresh(manual=True), "<Control>r"),
            ("pause", self._toggle_pause, "<Control>p"),
            ("search", lambda *_: self.search.grab_focus(), "<Control>f"),
            ("shortcuts", self._show_shortcuts, "<Control>question"),
            ("about", self._show_about, None),
        ):
            action = Gio.SimpleAction.new(name, None)
            action.connect("activate", handler)
            self.add_action(action)
            if shortcut:
                self.get_application().set_accels_for_action(f"win.{name}", [shortcut])
        return header

    def _content(self):
        heading = label("Network activity", "title-1")
        heading.update_property([Gtk.AccessibleProperty.LEVEL], [1])
        heading.set_hexpand(True)
        self.status = label("", "monitor-status")
        self.status_icon = Gtk.Image()
        self.status_pill = box(
            self.status_icon, self.status, spacing=6, css="status-pill"
        )
        self.status_pill.set_valign(Gtk.Align.CENTER)

        cards = box(spacing=10)
        cards.set_homogeneous(True)
        self.totals = []
        for title, icon_name, description in (
            ("Sockets", "network-wired-symbolic", "Visible TCP and UDP sockets"),
            (
                "TCP listeners",
                "network-server-symbolic",
                "TCP sockets in the LISTEN state",
            ),
            (
                "Processes",
                "application-x-executable-symbolic",
                "Distinct visible process IDs",
            ),
        ):
            icon = Gtk.Image.new_from_icon_name(icon_name)
            icon.set_pixel_size(16)
            title_label = label(title, "metric-title")
            title_label.set_ellipsize(Pango.EllipsizeMode.END)
            title_label.set_tooltip_text(title)
            count = label("—", "title-1", "metric-value")
            self.totals.append(count)
            card = box(
                box(icon, title_label, spacing=7),
                count,
                vertical=True,
                spacing=6,
                css="metric-card",
            )
            card.set_tooltip_text(description)
            cards.append(card)

        self.search = Gtk.SearchEntry(
            placeholder_text="Search process, PID, or address…", hexpand=True
        )
        self.search.set_key_capture_widget(self)
        self.search.connect("search-changed", self._filter_changed)
        self.scope = self._dropdown(SCOPE_NAMES, "Socket type")
        self.protocol = self._dropdown(PROTOCOL_NAMES, "Protocol")
        self.scope.connect("notify::selected", self._scope_changed)
        self.protocol.connect("notify::selected", self._filter_changed)
        filter_controls = box(self.scope, self.protocol, spacing=8)
        filters = box(self.search, filter_controls, spacing=8)

        section = label("Connections", "title-3")
        section.set_hexpand(True)
        self.visible_count = label("", "dim-label", "caption")
        section_header = box(section, self.visible_count, spacing=8)

        table = self._table()
        scroll = Gtk.ScrolledWindow(vexpand=True, child=table)
        scroll.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        self.empty = Adw.StatusPage()
        self.empty.set_vexpand(True)
        self.empty.add_css_class("compact")
        self.table_stack = Gtk.Stack(vexpand=True)
        self.table_stack.add_named(scroll, "table")
        self.table_stack.add_named(self.empty, "empty")
        self.table_stack.add_css_class("socket-table")

        self.footer = label("", "dim-label", "caption")
        self.footer.set_hexpand(True)
        self.footer.set_ellipsize(Pango.EllipsizeMode.END)
        self.permissions = Gtk.MenuButton(
            icon_name="dialog-information-symbolic",
            tooltip_text="About socket visibility",
        )
        self.permissions.add_css_class("flat")
        note = label(
            "Linux may hide some sockets or process details from your user account. "
            "The counts reflect this app’s view of the current network namespace."
        )
        note.set_wrap(True)
        note.set_max_width_chars(38)
        popover = Gtk.Popover()
        popover.set_child(note)
        self.permissions.set_popover(popover)
        footer = box(self.footer, self.permissions, spacing=8)

        content = box(
            box(heading, self.status_pill, spacing=12),
            cards,
            section_header,
            filters,
            self.table_stack,
            footer,
            vertical=True,
            spacing=12,
            css="explorer-content",
        )
        compact = Adw.Breakpoint.new(Adw.BreakpointCondition.parse("max-width: 760sp"))
        compact.add_setter(filters, "orientation", Gtk.Orientation.VERTICAL)
        compact.add_setter(content, "spacing", 8)
        compact.add_setter(cards, "spacing", 6)

        columns = table.get_columns()
        for index in (1, 2, 5):
            compact.add_setter(columns.get_item(index), "visible", False)
        for index in (0, 3, 4):
            compact.add_setter(columns.get_item(index), "fixed-width", 132)
        self.add_breakpoint(compact)
        self._update_table_status()
        self._update_status()
        return content

    def _dropdown(self, names, description):
        dropdown = Gtk.DropDown.new_from_strings(names)
        dropdown.set_tooltip_text(description)
        dropdown.update_property([Gtk.AccessibleProperty.LABEL], [description])
        return dropdown

    def _table(self):
        table = Gtk.ColumnView(show_row_separators=True, single_click_activate=True)
        table.add_css_class("data-table")
        table.update_property(
            [Gtk.AccessibleProperty.LABEL, Gtk.AccessibleProperty.DESCRIPTION],
            ["Connections", "Activate a row to inspect the socket and its process."],
        )
        table.connect("activate", self._inspect)
        columns = (
            (
                "Process",
                lambda row: row.process_label,
                lambda row: row.process_label.casefold(),
                146,
            ),
            (
                "PID",
                lambda row: str(row.pid) if row.pid is not None else "—",
                lambda row: row.pid if row.pid is not None else -1,
                67,
            ),
            ("Protocol", lambda row: row.protocol, lambda row: row.protocol, 82),
            (
                "Local address",
                lambda row: endpoint_text(row.local),
                lambda row: row.local,
                145,
            ),
            (
                "Remote address",
                lambda row: endpoint_text(row.remote),
                lambda row: row.remote,
                145,
            ),
            ("State", lambda row: row.state or "—", lambda row: row.state, 133),
        )
        for title, get_text, sort_key, width in columns:
            column = self._column(title, get_text, sort_key, width)
            table.append_column(column)

        self.sorted = Gtk.SortListModel.new(self.filtered, table.get_sorter())
        table.set_model(Gtk.NoSelection.new(self.sorted))
        table.sort_by_column(table.get_columns().get_item(0), Gtk.SortType.ASCENDING)
        return table

    def _column(self, title, get_text, sort_key, width):
        def setup(_factory, item):
            text = label("", "socket-cell")
            text.set_ellipsize(Pango.EllipsizeMode.END)
            if title == "PID" or title.endswith("address"):
                text.add_css_class("numeric")
            if title == "Process":
                text.add_css_class("process-name")
            item.set_child(text)

        def bind(_factory, item):
            connection = item.get_item().connection
            cell = item.get_child()
            value = get_text(connection)
            cell.set_label(value)
            cell.set_tooltip_text(value if value != "—" else None)
            if title == "State":
                cell.remove_css_class("established")
                cell.remove_css_class("listening")
                if connection.state == "ESTABLISHED":
                    cell.add_css_class("established")
                elif connection.is_listener:
                    cell.add_css_class("listening")

        def compare(first, second, *_):
            left = sort_key(first.connection)
            right = sort_key(second.connection)
            if left is None or right is None:
                return (left is not None) - (right is not None)
            return (left > right) - (left < right)

        factory = Gtk.SignalListItemFactory()
        factory.connect("setup", setup)
        factory.connect("bind", bind)
        column = Gtk.ColumnViewColumn.new(title, factory)
        column.set_fixed_width(width)
        column.set_resizable(True)
        column.set_expand(title.endswith("address") or title == "Process")
        column.set_sorter(Gtk.CustomSorter.new(compare))
        return column

    def _matches(self, row, *_):
        if not all(term in row.search_text for term in self.search_terms):
            return False
        connection = row.connection
        scope = self.scope.get_selected()
        if scope == 1:
            return connection.is_listener
        if scope == 2:
            return connection.is_bound_udp
        protocol = self.protocol.get_selected()
        return protocol == 0 or connection.protocol == PROTOCOL_NAMES[protocol]

    def _scope_changed(self, *_):
        self.protocol.set_sensitive(self.scope.get_selected() == 0)
        self._filter_changed()

    def _filter_changed(self, *_):
        self.search_terms = self.search.get_text().casefold().split()
        self.filter.changed(Gtk.FilterChange.DIFFERENT)
        self._update_table_status()

    def _update_table_status(self, *_):
        count = self.filtered.get_n_items()
        total = self.store.get_n_items()
        self.visible_count.set_label(f"{count:,} of {total:,}" if self.snapshot else "")
        if count:
            self.table_stack.set_visible_child_name("table")
            return

        if self.snapshot is None and not self.error:
            icon, title, message = ("network-wired-symbolic", "Reading sockets", "")
        elif self.snapshot is None:
            icon, title, message = (
                "dialog-warning-symbolic",
                "Couldn’t read sockets",
                "Use Refresh to try again.",
            )
        elif total:
            icon, title, message = (
                "system-search-symbolic",
                "No matching sockets",
                "Try another search or filter.",
            )
        else:
            icon, title, message = (
                "network-wired-symbolic",
                "No visible sockets",
                "New sockets appear while monitoring.",
            )
        self.empty.set_icon_name(icon)
        self.empty.set_title(title)
        self.empty.set_description(message)
        self.table_stack.set_visible_child_name("empty")

    def _update_status(self):
        if self.demo:
            text, icon, css = "Demo data", "view-preview-symbolic", "demo"
            footer = "Fictional sockets for previewing the interface"
        elif self.error:
            text, icon, css = "Refresh failed", "dialog-warning-symbolic", "warning"
            footer = "Unable to read local sockets"
        elif self.paused:
            text, icon, css = "Paused", "media-playback-pause-symbolic", "paused"
            footer = "Automatic refresh is paused"
        else:
            text, icon, css = "Monitoring", "media-record-symbolic", "monitoring"
            footer = f"Refreshes every {REFRESH_INTERVAL} seconds"

        if self.snapshot and not self.demo:
            footer += f"  ·  Last snapshot {self.snapshot.captured_at:%H:%M:%S}"
        for style in ("demo", "warning", "paused", "monitoring"):
            self.status_pill.remove_css_class(style)
        self.status_pill.add_css_class(css)
        self.status.set_label(text)
        self.status_icon.set_from_icon_name(icon)
        self.footer.set_label(footer)
        self.footer.set_tooltip_text(footer)

    def _set_pause_button(self):
        icon = (
            "media-playback-start-symbolic"
            if self.paused
            else "media-playback-pause-symbolic"
        )
        text = "Resume monitoring" if self.paused else "Pause monitoring"
        self.pause_button.set_icon_name(icon)
        self.pause_button.set_tooltip_text(f"{text} (Ctrl+P)")

    def _toggle_pause(self, *_):
        self.paused = not self.paused
        if self.paused and self.in_flight and self.snapshot is not None:
            self.discard_pending = True
        self._set_pause_button()
        self._update_status()
        if not self.paused:
            self._refresh()

    def _tick(self):
        self._refresh()
        return GLib.SOURCE_CONTINUE

    def _refresh(self, manual=False):
        if self.in_flight:
            if manual:
                self.discard_pending = False
            return
        if self.paused and not manual:
            return
        self.in_flight = True
        self.discard_pending = False
        Thread(target=self._read_snapshot, name="socket-collector", daemon=True).start()

    def _read_snapshot(self):
        try:
            snapshot = self.collect()
        except Exception:
            LOGGER.exception("Unable to collect socket data")
            snapshot = None
        GLib.idle_add(self._apply_snapshot, snapshot)

    def _apply_snapshot(self, snapshot):
        self.in_flight = False
        if self.closed or self.discard_pending:
            return GLib.SOURCE_REMOVE
        self.error = snapshot is None
        if snapshot is not None:
            previous = self.snapshot
            self.snapshot = snapshot
            if previous is None or snapshot.connections != previous.connections:
                current = {row.connection: row for row in self.store}
                rows = [
                    current.get(connection) or SocketRow(connection)
                    for connection in snapshot.connections
                ]
                self.store.splice(0, self.store.get_n_items(), rows)
            for widget, value in zip(
                self.totals,
                (
                    len(snapshot.connections),
                    snapshot.listener_count,
                    snapshot.process_count,
                ),
            ):
                widget.set_label(f"{value:,}")
        self._update_status()
        self._update_table_status()
        return GLib.SOURCE_REMOVE

    def _close(self, *_):
        self.closed = True
        GLib.source_remove(self.timer)
        return False

    def _inspect(self, _table, position):
        row = self.sorted.get_item(position)
        if row is None:
            return
        connection = row.connection
        details = Adw.Dialog(title="Socket Details", content_width=500)
        page = Adw.PreferencesPage()
        process = Adw.PreferencesGroup(title="Process")
        fields = Adw.PreferencesGroup(title="Socket")
        for group, name, value in (
            (process, "Name", connection.process_label),
            (
                process,
                "PID",
                str(connection.pid) if connection.pid is not None else None,
            ),
            (process, "Executable", connection.executable),
            (fields, "Protocol", f"{connection.protocol} · {connection.family}"),
            (
                fields,
                "Local address",
                str(connection.local) if connection.local else None,
            ),
            (
                fields,
                "Remote address",
                str(connection.remote) if connection.remote else None,
            ),
            (fields, "State", connection.state),
        ):
            field = Adw.ActionRow(
                title=name,
                subtitle=value or "Unavailable",
                use_markup=False,
                subtitle_selectable=True,
            )
            group.add(field)
        if connection.is_wildcard:
            fields.set_description(
                f"The socket is bound to all {connection.family} interfaces."
            )
        page.add(process)
        page.add(fields)
        toolbar = Adw.ToolbarView()
        toolbar.add_top_bar(Adw.HeaderBar())
        toolbar.set_content(page)
        details.set_child(toolbar)
        details.present(self)

    def _show_shortcuts(self, *_):
        dialog = Adw.ShortcutsDialog()
        section = Adw.ShortcutsSection(title="Network Explorer")
        for title, accelerator in (
            ("Search sockets", "<Control>f"),
            ("Refresh now", "<Control>r"),
            ("Pause or resume monitoring", "<Control>p"),
            ("Keyboard shortcuts", "<Control>question"),
        ):
            section.add(Adw.ShortcutsItem(title=title, accelerator=accelerator))
        dialog.add(section)
        dialog.present(self)

    def _show_about(self, *_):
        dialog = Adw.AboutDialog(
            application_name="SocketForge",
            application_icon=APP_ID,
            developer_name="SocketForge contributors",
            version=VERSION,
            website="https://github.com/tobiasGuta/SocketForge",
            issue_url="https://github.com/tobiasGuta/SocketForge/issues",
        )
        dialog.present(self)


class SocketForge(Adw.Application):
    def __init__(self, demo=False):
        flags = (
            Gio.ApplicationFlags.NON_UNIQUE
            if demo
            else Gio.ApplicationFlags.DEFAULT_FLAGS
        )
        super().__init__(application_id=APP_ID, flags=flags)
        self.demo = demo

    def do_startup(self):
        Adw.Application.do_startup(self)
        display = Gdk.Display.get_default()
        assets = Path(__file__).with_name("assets")
        Gtk.IconTheme.get_for_display(display).add_search_path(str(assets))
        Gtk.Window.set_default_icon_name(APP_ID)
        provider = Gtk.CssProvider()
        provider.load_from_path(str(assets / "style.css"))
        Gtk.StyleContext.add_provider_for_display(
            display, provider, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION
        )

    def do_activate(self):
        window = self.get_active_window()
        if window is None:
            window = Explorer(self, self.demo)
        window.present()
