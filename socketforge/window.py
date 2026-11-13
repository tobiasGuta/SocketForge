"""GTK4 and Libadwaita interface for the socket explorer."""

import logging
import sqlite3
from datetime import datetime
from itertools import islice
from pathlib import Path
from threading import Thread

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gdk, Gio, GLib, GObject, Gtk, Pango

from . import APP_ID, VERSION
from .demo import collect_demo
from .diagnostics import rates
from .listeners import inspect_listener
from .network import collect
from .timeline import Event, Session, clear_history, load_recent, save

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


class EventRow(GObject.Object):
    def __init__(self, event):
        super().__init__()
        self.event = event
        connection = event.connection.search_text if event.connection else ""
        self.search_text = (
            f"{event.kind} {event.detail} {event.source} {connection}".casefold()
        )


class Explorer(Adw.ApplicationWindow):
    def __init__(self, application, demo, trace=None):
        super().__init__(application=application, title="SocketForge")
        self.set_default_size(1120, 740)
        self.set_size_request(460, 440)
        self.demo = demo
        self.trace = trace
        self.trace_dropped = 0
        self.trace_status = None
        self.session = None
        self.rendered_events = 0
        self.previous_diagnostics = None
        self.rate_baseline = None
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
        if not self.demo:
            menu.append("Saved Sessions", "win.history")
            menu.append("Clear Saved Sessions", "win.clear-history")
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
            ("search", self._focus_search, "<Control>f"),
            ("shortcuts", self._show_shortcuts, "<Control>question"),
            ("about", self._show_about, None),
            ("history", self._show_history, None),
            ("clear-history", self._confirm_clear_history, None),
        ):
            action = Gio.SimpleAction.new(name, None)
            action.connect("activate", handler)
            self.add_action(action)
            if shortcut:
                self.get_application().set_accels_for_action(f"win.{name}", [shortcut])
        return header

    def _focus_search(self, *_):
        view = self.views.get_visible_child_name()
        if view == "timeline":
            self.timeline_search.grab_focus()
        else:
            self.views.set_visible_child_name("live")
            self.search.grab_focus()

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

        live = box(
            box(heading, self.status_pill, spacing=12),
            cards,
            section_header,
            filters,
            self.table_stack,
            footer,
            vertical=True,
            spacing=12,
        )
        self.views = Adw.ViewStack(vexpand=True)
        self.views.add_titled_with_icon(live, "live", "Live", "network-wired-symbolic")
        self.views.add_titled_with_icon(
            self._listeners_view(),
            "listeners",
            "Listening Ports",
            "network-server-symbolic",
        )
        self.views.add_titled_with_icon(
            self._timeline_view(),
            "timeline",
            "Timeline",
            "document-open-recent-symbolic",
        )
        switcher = Adw.ViewSwitcher(
            stack=self.views, policy=Adw.ViewSwitcherPolicy.WIDE
        )
        switcher.set_halign(Gtk.Align.CENTER)
        content = box(
            switcher, self.views, vertical=True, spacing=12, css="explorer-content"
        )
        compact = Adw.Breakpoint.new(Adw.BreakpointCondition.parse("max-width: 760sp"))
        compact.add_setter(filters, "orientation", Gtk.Orientation.VERTICAL)
        compact.add_setter(live, "spacing", 8)
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

    def _listeners_view(self):
        heading = label("Listening ports", "title-1")
        subtitle = label("TCP listeners in the current network namespace", "dim-label")
        subtitle.set_wrap(True)
        self.listeners = Gtk.FilterListModel.new(
            self.store, Gtk.CustomFilter.new(lambda row, *_: row.connection.is_listener)
        )
        view = self._list_view(
            self.listeners, self._listener_item, self._inspect_listener_row
        )
        self.listener_empty = Adw.StatusPage(
            icon_name="network-server-symbolic", title="No visible TCP listeners"
        )
        self.listener_empty.add_css_class("compact")
        self.listener_stack = Gtk.Stack(vexpand=True)
        self.listener_stack.add_named(view, "list")
        self.listener_stack.add_named(self.listener_empty, "empty")
        self.listeners.connect("items-changed", self._update_listeners)
        self._update_listeners()
        return box(heading, subtitle, self.listener_stack, vertical=True, spacing=10)

    def _update_listeners(self, *_):
        self.listener_stack.set_visible_child_name(
            "list" if self.listeners.get_n_items() else "empty"
        )

    def _listener_item(self, row):
        connection = row.connection
        pid = f" · PID {connection.pid}" if connection.pid is not None else ""
        return (
            str(connection.local),
            f"{connection.process_label}{pid} · {connection.family}",
            True,
        )

    def _inspect_listener_row(self, _view, position):
        row = self.listeners.get_item(position)
        if row:
            self._show_socket(row.connection, live=True)

    def _list_view(self, model, describe, activate):
        def setup(_factory, item):
            title = label("", "heading")
            subtitle = label("", "dim-label", "caption")
            for text in (title, subtitle):
                text.set_ellipsize(Pango.EllipsizeMode.END)
            item.set_child(
                box(title, subtitle, vertical=True, spacing=3, css="event-row")
            )

        def bind(_factory, item):
            title, subtitle, clickable = describe(item.get_item())
            row = item.get_child()
            row.get_first_child().set_label(title)
            row.get_last_child().set_label(subtitle)
            row.set_tooltip_text(subtitle or None)
            item.set_activatable(clickable)

        factory = Gtk.SignalListItemFactory()
        factory.connect("setup", setup)
        factory.connect("bind", bind)
        view = Gtk.ListView(
            model=Gtk.NoSelection.new(model),
            factory=factory,
            single_click_activate=True,
            show_separators=True,
        )
        view.connect("activate", activate)
        scroll = Gtk.ScrolledWindow(vexpand=True, child=view)
        scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        scroll.add_css_class("socket-table")
        return scroll

    def _timeline_view(self):
        title = label("Investigation timeline", "title-1")
        title.set_wrap(True)
        self.session_status = label(
            "Start a session to record socket changes.", "dim-label"
        )
        self.session_status.set_wrap(True)
        self.trace_label = label("", "caption", "dim-label")
        self.trace_label.set_wrap(True)
        self.trace_label.set_visible(self.trace is not None)
        self.session_button = Gtk.Button(label="Start Session")
        self.session_button.add_css_class("suggested-action")
        self.session_button.connect("clicked", self._toggle_session)
        self.persist = Gtk.CheckButton(label="Save locally")
        self.persist.set_tooltip_text("Keep up to 20 completed sessions for seven days")
        self.persist.set_visible(not self.demo)
        self.event_store = Gio.ListStore.new(EventRow)
        self.timeline_search = Gtk.SearchEntry(
            placeholder_text="Search events, processes, or addresses…", hexpand=True
        )
        self.timeline_search.connect("search-changed", self._timeline_filter_changed)
        self.event_filter = Gtk.CustomFilter.new(self._matches_event)
        self.filtered_events = Gtk.FilterListModel.new(
            self.event_store, self.event_filter
        )
        events = self._list_view(
            self.filtered_events, self._describe_event, self._open_event
        )
        empty = Adw.StatusPage(
            icon_name="document-open-recent-symbolic", title="No events to show"
        )
        empty.add_css_class("compact")
        self.event_stack = Gtk.Stack(vexpand=True)
        self.event_stack.add_named(events, "events")
        self.event_stack.add_named(empty, "empty")
        self.event_stack.set_visible_child_name("empty")
        self.filtered_events.connect("items-changed", self._update_event_stack)
        return box(
            title,
            self.session_status,
            self.trace_label,
            box(self.session_button, self.persist, spacing=12),
            self.timeline_search,
            self.event_stack,
            vertical=True,
            spacing=10,
        )

    def _matches_event(self, row, *_):
        terms = self.timeline_search.get_text().casefold().split()
        return all(term in row.search_text for term in terms)

    def _timeline_filter_changed(self, *_):
        self.event_filter.changed(Gtk.FilterChange.DIFFERENT)

    def _update_event_stack(self, *_):
        self.event_stack.set_visible_child_name(
            "events" if self.filtered_events.get_n_items() else "empty"
        )

    def _describe_event(self, row):
        event = row.event
        pieces = [f"{event.time:%H:%M:%S}", event.source]
        if event.connection:
            connection = event.connection
            pieces.extend((connection.process_label, endpoint_text(connection.local)))
            if connection.remote:
                pieces.append(str(connection.remote))
        if event.detail:
            pieces.append(event.detail)
        return event.kind, " · ".join(pieces), event.connection is not None

    def _open_event(self, _view, position):
        row = self.filtered_events.get_item(position)
        if row and row.event.connection:
            self._show_socket(row.event.connection)

    def _show_events(self, events):
        rows = [EventRow(event) for event in reversed(events)]
        self.event_store.splice(0, self.event_store.get_n_items(), rows)

    def _toggle_session(self, *_):
        if self.session and self.session.active:
            self._drain_trace()
            self._finish_session()
            return
        self._drain_trace()
        self.session = Session(persist=self.persist.get_active() and not self.demo)
        self.session_started_at = datetime.now().astimezone()
        self._show_events([])
        self.rendered_events = 0
        self.session_button.set_label("Stop Session")
        self.session_button.remove_css_class("suggested-action")
        self.persist.set_sensitive(False)
        self.session_status.set_label("Waiting for the baseline snapshot…")
        self._refresh(manual=True)

    def _finish_session(self):
        self.session.active = False
        self.session_button.set_label("Start Session")
        self.session_button.add_css_class("suggested-action")
        self.persist.set_sensitive(True)
        count = len(self.session.events)
        self.session_status.set_label(f"Session ended · {count:,} retained events")
        if self.session.persist:
            try:
                save(self.session)
                self.session_status.set_label(
                    f"Session saved locally · {count:,} retained events"
                )
            except (OSError, sqlite3.Error):
                LOGGER.exception("Unable to save session")
                self.toasts.add_toast(Adw.Toast(title="Couldn’t save session"))

    def _update_session(self):
        new_count = self.session.event_count - self.rendered_events
        if new_count:
            count = min(new_count, len(self.session.events))
            rows = [
                EventRow(event)
                for event in islice(reversed(self.session.events), count)
            ]
            self.event_store.splice(0, 0, rows)
            excess = self.event_store.get_n_items() - len(self.session.events)
            if excess:
                self.event_store.splice(len(self.session.events), excess, [])
            self.rendered_events = self.session.event_count
        count = len(self.session.events)
        self.session_status.set_label(f"Recording · {count:,} retained events")

    def _drain_trace(self):
        if not self.trace:
            return
        events = self.trace.drain()
        dropped = self.trace.dropped
        status = self.trace.status
        self.trace_label.set_label(status)
        if self.session and self.session.active:
            events = [
                event for event in events if event.time >= self.session_started_at
            ]
            if status.startswith("Trace ended") and status != self.trace_status:
                events.append(
                    Event(
                        datetime.now().astimezone(),
                        "Trace ended",
                        detail=status,
                        source="Kernel trace",
                    )
                )
            if dropped > self.trace_dropped:
                events.append(
                    Event(
                        datetime.now().astimezone(),
                        "Trace event loss",
                        detail=f"{dropped - self.trace_dropped:,} events dropped by the app",
                        source="Kernel trace",
                    )
                )
            if events:
                self.session.add(*events)
                self._update_session()
        self.trace_status = status
        self.trace_dropped = dropped

    def _show_history(self, *_):
        if self.session and self.session.active:
            self.toasts.add_toast(
                Adw.Toast(title="Stop the active session to open a saved session")
            )
            return
        try:
            sessions = load_recent()
        except (OSError, sqlite3.Error, ValueError):
            LOGGER.exception("Unable to load saved sessions")
            self.toasts.add_toast(Adw.Toast(title="Couldn’t read saved sessions"))
            return
        dialog = Adw.Dialog(
            title="Saved Sessions", content_width=470, content_height=390
        )
        page = Adw.PreferencesPage()
        group = Adw.PreferencesGroup(
            description="Sessions are stored locally for up to seven days."
            if sessions
            else "There are no saved sessions."
        )
        for timestamp, events in sessions:
            row = Adw.ActionRow(
                title=f"{timestamp:%b %d, %H:%M:%S}",
                subtitle=f"{len(events):,} retained events",
                activatable=True,
            )
            row.add_suffix(Gtk.Image.new_from_icon_name("go-next-symbolic"))
            row.connect("activated", self._open_session, dialog, timestamp, events)
            group.add(row)
        page.add(group)
        toolbar = Adw.ToolbarView(content=page)
        toolbar.add_top_bar(Adw.HeaderBar())
        dialog.set_child(toolbar)
        dialog.present(self)

    def _open_session(self, _row, dialog, timestamp, events):
        self._show_events(events)
        self.session_status.set_label(f"Saved session · {timestamp:%b %d, %H:%M:%S}")
        self.views.set_visible_child_name("timeline")
        dialog.close()

    def _confirm_clear_history(self, *_):
        dialog = Adw.AlertDialog(
            heading="Clear saved sessions?",
            body="This removes all sessions stored on this device.",
        )
        dialog.add_response("cancel", "Cancel")
        dialog.add_response("clear", "Clear")
        dialog.set_response_appearance("clear", Adw.ResponseAppearance.DESTRUCTIVE)
        dialog.set_close_response("cancel")
        dialog.connect("response::clear", self._clear_history)
        dialog.present(self)

    def _clear_history(self, *_):
        try:
            clear_history()
        except (OSError, sqlite3.Error):
            LOGGER.exception("Unable to clear saved sessions")
            self.toasts.add_toast(Adw.Toast(title="Couldn’t clear saved sessions"))
            return
        self.toasts.add_toast(Adw.Toast(title="Saved sessions cleared"))

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
        self.previous_diagnostics = None
        self.rate_baseline = None
        if self.session and self.session.active:
            self.session.gap(
                datetime.now().astimezone(),
                "Snapshot monitoring paused"
                if self.paused
                else "Snapshot monitoring resumed",
            )
            self._update_session()
        if self.paused and self.in_flight and self.snapshot is not None:
            self.discard_pending = True
        self._set_pause_button()
        self._update_status()
        if not self.paused:
            self._refresh()

    def _tick(self):
        self._drain_trace()
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
        if self.session and self.session.active:
            if snapshot is None:
                self.session.gap(datetime.now().astimezone(), "Snapshot read failed")
            elif snapshot.captured_at >= self.session_started_at:
                last = self.session.last_snapshot_at
                if (
                    last
                    and (snapshot.captured_at - last).total_seconds()
                    > REFRESH_INTERVAL * 3
                ):
                    self.session.gap(
                        snapshot.captured_at, "Snapshot sampling was interrupted"
                    )
                self.session.observe(snapshot)
            self._update_session()
        self.previous_diagnostics = self.rate_baseline if snapshot else None
        self.rate_baseline = (
            snapshot.diagnostics if snapshot and not self.paused else None
        )
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
        if self.session and self.session.active:
            self._drain_trace()
            self._finish_session()
        self.closed = True
        GLib.source_remove(self.timer)
        return False

    def _inspect(self, _table, position):
        row = self.sorted.get_item(position)
        if row is None:
            return
        self._show_socket(row.connection, live=True)

    def _show_socket(self, connection, live=False):
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
        if live:
            self._add_tcp_details(page, connection)
        if live and connection.is_listener and connection.local:
            self._add_listener_details(page, connection)
        toolbar = Adw.ToolbarView()
        toolbar.add_top_bar(Adw.HeaderBar())
        toolbar.set_content(page)
        details.set_child(toolbar)
        details.present(self)

    def _add_tcp_details(self, page, connection):
        if connection.protocol != "TCP" or connection.is_listener or self.demo:
            return
        diagnostics = self.snapshot.diagnostics
        info = diagnostics.sockets.get(connection.inode) if diagnostics else None
        group = Adw.PreferencesGroup(title="TCP Diagnostics")
        page.add(group)
        if not info:
            group.set_description("Kernel counters are unavailable for this socket.")
            return
        group.set_description("TCP data sampled at the last refresh.")
        values = [
            (
                "Round-trip time",
                f"{info.rtt_ms:.2f} ms" if info.rtt_ms else "Unavailable",
            ),
            ("Retransmissions", f"{info.retransmissions:,}"),
            ("Bytes acknowledged", f"{info.acked:,}"),
            ("Bytes received", f"{info.received:,}"),
        ]
        previous = self.previous_diagnostics
        speed = (
            rates(
                info,
                previous.sockets.get(connection.inode),
                diagnostics.sampled_at - previous.sampled_at,
            )
            if previous
            else None
        )
        if speed is not None:
            values.extend(
                (
                    ("Acknowledged send rate", f"{speed[0] / 1024:,.1f} KiB/s"),
                    ("Receive rate", f"{speed[1] / 1024:,.1f} KiB/s"),
                )
            )
        for title, value in values:
            group.add(Adw.ActionRow(title=title, subtitle=value))

    def _add_listener_details(self, page, connection):
        group = Adw.PreferencesGroup(
            title="Listener Context", description="Reading local configuration…"
        )
        page.add(group)

        def apply(values):
            if self.closed:
                return GLib.SOURCE_REMOVE
            group.set_description(
                "External reachability is unknown. Zones shown are interface assignments."
            )
            for title, value in values:
                group.add(
                    Adw.ActionRow(
                        title=title,
                        subtitle=value or "Unavailable",
                        use_markup=False,
                        subtitle_selectable=True,
                    )
                )
            return GLib.SOURCE_REMOVE

        def read():
            if self.demo:
                values = (
                    (
                        "Bind scope",
                        "All interfaces" if connection.is_wildcard else "Loopback",
                    ),
                    (
                        "Systemd unit",
                        "sshd.service" if connection.process == "sshd" else None,
                    ),
                )
            else:
                try:
                    values = inspect_listener(connection)
                except (OSError, ValueError):
                    LOGGER.exception("Unable to read listener context")
                    values = (("Listener context", None),)
            GLib.idle_add(apply, values)

        Thread(target=read, name="listener-context", daemon=True).start()

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
    def __init__(self, demo=False, trace=None):
        flags = (
            Gio.ApplicationFlags.NON_UNIQUE
            if demo or trace is not None
            else Gio.ApplicationFlags.DEFAULT_FLAGS
        )
        super().__init__(application_id=APP_ID, flags=flags)
        self.demo = demo
        self.trace = trace

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
            window = Explorer(self, self.demo, self.trace)
        window.present()
