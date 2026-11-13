"""GNOME views and actions for the local security monitor."""

import json
import os
import subprocess
from collections import Counter, defaultdict
from dataclasses import replace
from datetime import datetime
from ipaddress import ip_network
from pathlib import Path
from threading import Thread
from time import time

from gi.repository import Adw, Gio, GLib, Gtk

from . import firewall, host
from .intelligence import classify, lookup
from .listeners import systemd_unit
from .security import ACTIVITY_KINDS, Monitor, app_key, direction
from .timeline import Event
from .widgets import EventRow, box, label


class SecurityViews:
    def init_security(self):
        self.monitor = Monitor()
        self.alerts = []
        self.blocks = {}
        self.hit_counts = Counter()
        self.flow_counts = Counter()
        self.alert_id = 0
        self.sent_banners = set()
        self.last_banner = 0
        self.firewall_cursor = None
        self.firewall_started = time()
        self.firewall_busy = False
        self.host_busy = False
        self.host_cursor = None
        self.host_state = set()
        self.host_label = ""
        self.firewall_status = "Waiting for the kernel journal"
        self.settings_path = (
            Path(os.getenv("XDG_CONFIG_HOME") or Path.home() / ".config")
            / "socketforge/settings.json"
        )
        self.settings = {
            "notifications": False,
            "quiet_until": 0,
            "muted": [],
            "background": False,
        }
        if not self.demo:
            try:
                data = json.loads(self.settings_path.read_text())
                for key, default in self.settings.items():
                    if isinstance(data.get(key), type(default)):
                        self.settings[key] = data[key]
            except (OSError, ValueError, AttributeError):
                pass

    def _set(self, key, value):
        self.settings[key] = value
        if self.demo:
            return
        try:
            self.settings_path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
            temp = self.settings_path.with_suffix(f".{os.getpid()}.tmp")
            temp.write_text(json.dumps(self.settings))
            temp.replace(self.settings_path)
        except OSError:
            self._toast("Couldn’t save settings")

    def _toast(self, title):
        self.toasts.add_toast(Adw.Toast(title=title))

    def _work(self, operation, apply, failed=None):
        def run():
            try:
                result = operation()
            except (OSError, ValueError, subprocess.SubprocessError) as error:
                if failed:
                    GLib.idle_add(failed, getattr(error, "stderr", None) or str(error))
            else:
                GLib.idle_add(apply, result)

        Thread(target=run, daemon=True).start()

    def _section(self, title, description=None):
        return Adw.PreferencesGroup(title=title, description=description)

    def _field(self, group, title, value):
        row = Adw.ActionRow(
            title=title, subtitle=str(value), use_markup=False, subtitle_selectable=True
        )
        group.add(row)
        return row

    def _button(self, group, title, description, callback):
        row = Adw.ActionRow(
            title=title, subtitle=description, activatable=True, use_markup=False
        )
        row.add_suffix(Gtk.Image.new_from_icon_name("go-next-symbolic"))
        row.connect("activated", callback)
        group.add(row)
        return row

    def _dialog(self, title, page):
        dialog = Adw.Dialog(title=title, content_width=540, content_height=560)
        toolbar = Adw.ToolbarView(content=page)
        toolbar.add_top_bar(Adw.HeaderBar())
        dialog.set_child(toolbar)
        dialog.present(self)
        return dialog

    def _activity_view(self):
        self.activity_store = Gio.ListStore.new(EventRow)
        self.activity_search = Gtk.SearchEntry(
            placeholder_text="Search activity…", hexpand=True
        )
        self.activity_kind = self._dropdown(ACTIVITY_KINDS, "Traffic direction")
        self.activity_filter = Gtk.CustomFilter.new(self._matches_activity)
        self.activity_model = Gtk.FilterListModel.new(
            self.activity_store, self.activity_filter
        )
        self.activity_search.connect("search-changed", self._activity_changed)
        self.activity_kind.connect("notify::selected", self._activity_changed)
        by_app = Gtk.Button(
            icon_name="view-list-symbolic", tooltip_text="Group activity by app"
        )
        by_app.connect("clicked", lambda *_: self._grouped_activity())
        self.activity_status = label("", "dim-label", "caption")
        self.activity_status.set_wrap(True)
        view = self._list_view(
            self.activity_model, self._describe_activity, self._open_activity
        )
        view.get_child().add_css_class("activity-list")
        self.activity_empty = Adw.StatusPage(
            icon_name="network-wired-symbolic", title="No matching activity"
        )
        self.activity_empty.add_css_class("compact")
        self.activity_stack = Gtk.Stack(vexpand=True)
        self.activity_stack.add_named(view, "list")
        self.activity_stack.add_named(self.activity_empty, "empty")
        self.activity_model.connect("items-changed", self._refresh_activity_status)
        self._refresh_activity_status()
        return box(
            label("Network activity", "title-1"),
            self.activity_status,
            box(self.activity_search, self.activity_kind, by_app, spacing=8),
            self.activity_stack,
            vertical=True,
            spacing=10,
        )

    def _matches_activity(self, row, *_):
        selected = self.activity_kind.get_selected()
        return (
            selected == 0 or direction(row.event) == ACTIVITY_KINDS[selected]
        ) and all(
            word in row.search_text
            for word in self.activity_search.get_text().casefold().split()
        )

    def _activity_changed(self, *_):
        self.activity_filter.changed(Gtk.FilterChange.DIFFERENT)
        self._refresh_activity_status()

    def _refresh_activity_status(self, *_):
        coverage = "Demo data" if self.demo else "Socket snapshots"
        if self.trace:
            coverage += " · TCP stream: " + self.trace.status
        if self.host_label:
            coverage += " · " + self.host_label
        self.activity_status.set_label(
            f"{coverage} · {self.activity_model.get_n_items():,} shown\n"
            f"Firewall · {self.firewall_status}"
            if not self.demo
            else coverage
        )
        self.activity_stack.set_visible_child_name(
            "list" if self.activity_model.get_n_items() else "empty"
        )

    def _describe_activity(self, row):
        title, detail, clickable = self._describe_event(row)
        if row.event.source == "Firewall":
            key = row.event.detail.split()[0]
            detail += f" · {self.hit_counts[key]:,} logged hits for rule"
        if row.event.source == "Host conntrack":
            detail += (
                f" · {self.flow_counts[self._activity_key(row.event)]:,} observed flows"
            )
        return f"{direction(row.event)} · {title}", detail, clickable

    def _open_activity(self, _list, position):
        row = self.activity_model.get_item(position)
        if row and row.event.connection:
            self._show_socket(row.event.connection, event=row.event)

    @staticmethod
    def _activity_key(event):
        if event.source == "Firewall":
            return event.detail.split()[0]
        if event.source == "Host conntrack" and event.connection:
            row = event.connection
            return event.kind, row.local, row.remote
        return None

    def _record(self, events):
        if not events or self.closed:
            return
        rows = []
        merged = set()
        owners = (
            {row.pid: row for row in self.snapshot.connections if row.pid}
            if self.snapshot
            else {}
        )
        for event in reversed(events):
            key = self._activity_key(event)
            if event.source == "Firewall":
                self.hit_counts[key] += 1
            elif key:
                self.flow_counts[key] += 1
            if key and key in merged:
                continue
            if key:
                merged.add(key)
            connection = event.connection
            if connection and connection.pid and connection.started is None:
                owner = owners.get(connection.pid)
                if (
                    owner
                    and owner.started
                    and owner.started <= event.time.timestamp()
                    and connection.process
                    and owner.process_label.startswith(connection.process)
                ):
                    event = replace(
                        event,
                        connection=replace(
                            connection,
                            process=owner.process,
                            executable=owner.executable,
                            parent=owner.parent,
                            started=owner.started,
                        ),
                    )
            rows.append(EventRow(event))
        for row in reversed(rows):
            matched = self.monitor.alert(row.event)
            if matched:
                self._add_alert(row.event, *matched)
        if merged:
            rows.extend(
                row
                for row in self.activity_store
                if self._activity_key(row.event) not in merged
            )
            self.activity_store.splice(
                0, self.activity_store.get_n_items(), rows[:2000]
            )
        else:
            self.activity_store.splice(0, 0, rows[:2000])
            excess = self.activity_store.get_n_items() - 2000
            if excess > 0:
                self.activity_store.splice(2000, excess, [])
        if len(self.hit_counts) + len(self.flow_counts) > 4096:
            retained = {self._activity_key(row.event) for row in self.activity_store}
            self.hit_counts = Counter(
                {
                    key: value
                    for key, value in self.hit_counts.items()
                    if key in retained
                }
            )
            self.flow_counts = Counter(
                {
                    key: value
                    for key, value in self.flow_counts.items()
                    if key in retained
                }
            )

    def _alerts_view(self):
        self.alert_store = Gio.ListStore.new(EventRow)
        self.notifications = Adw.SwitchRow(
            title="Desktop Notifications", subtitle="Show important alerts in GNOME"
        )
        self.notifications.set_active(self.settings["notifications"])
        self.notifications.connect("notify::active", self._notify_switch)
        group = self._section("Notifications")
        group.add(self.notifications)
        self.quiet_row = self._button(
            group, "Pause banners for 1 hour", "", self._pause_banners
        )
        self._update_quiet()
        background = Adw.SwitchRow(
            title="Keep monitoring without a tray icon",
            subtitle="Continue after closing even when the desktop has no tray",
        )
        background.set_active(self.settings["background"])
        background.set_sensitive(not self.demo)
        background.connect(
            "notify::active", lambda row, *_: self._set("background", row.get_active())
        )
        group.add(background)
        self.alert_empty = Adw.StatusPage(
            icon_name="preferences-system-notifications-symbolic",
            title="No alerts yet",
            description="New non-loopback TCP listeners appear here.",
        )
        self.alert_empty.add_css_class("compact")
        self.alert_stack = Gtk.Stack(vexpand=True)
        self.alert_stack.add_named(self.alert_empty, "empty")
        self.alert_stack.add_named(
            self._list_view(self.alert_store, self._describe_event, self._open_alert),
            "list",
        )
        self.alert_stack.set_visible_child_name("empty")
        return box(
            label("Alerts", "title-1"),
            group,
            self.alert_stack,
            vertical=True,
            spacing=10,
        )

    def _notify_switch(self, row, *_):
        self._set("notifications", row.get_active())
        if not row.get_active():
            for alert_id in self.sent_banners:
                self.get_application().withdraw_notification(alert_id)
            self.sent_banners.clear()

    def _pause_banners(self, *_):
        self._set(
            "quiet_until",
            int(time()) + 3600 if self.settings["quiet_until"] <= time() else 0,
        )
        self._update_quiet()

    def _update_quiet(self):
        paused = self.settings["quiet_until"] > time()
        self.quiet_row.set_title(
            "Resume banners" if paused else "Pause banners for 1 hour"
        )
        self.quiet_row.set_subtitle(
            datetime.fromtimestamp(self.settings["quiet_until"]).strftime(
                "Paused until %H:%M"
            )
            if paused
            else ""
        )

    def _add_alert(self, event, rule, reason):
        self.alert_id += 1
        identifier = f"socketforge-alert-{os.getpid()}-{self.alert_id}"
        self.alerts.insert(0, (identifier, event, rule, reason))
        self.alert_store.insert(
            0,
            EventRow(
                type(event)(
                    event.time, reason, event.connection, event.detail, event.source
                )
            ),
        )
        if len(self.alerts) > 300:
            expired = self.alerts.pop()[0]
            if expired in self.sent_banners:
                self.get_application().withdraw_notification(expired)
                self.sent_banners.remove(expired)
            self.alert_store.remove(300)
        self.alert_stack.set_visible_child_name("list")
        key = f"{rule}:{app_key(event.connection)}"
        if (
            self.demo
            or not self.settings["notifications"]
            or self.settings["quiet_until"] > time()
            or key in self.settings["muted"]
            or time() - self.last_banner < 15
        ):
            return
        self.last_banner = time()
        banner = Gio.Notification.new(reason)
        endpoint = event.connection.remote or event.connection.local
        banner.set_body(
            f"{event.connection.process_label} · {endpoint} · {event.time:%H:%M}"
        )
        banner.set_default_action_and_target_value(
            "app.open-alert", GLib.Variant("s", identifier)
        )
        self.get_application().send_notification(identifier, banner)
        self.sent_banners.add(identifier)

    def open_alert_id(self, identifier):
        self.views.set_visible_child_name("alerts")
        for position, (alert_id, *_) in enumerate(self.alerts):
            if alert_id == identifier:
                self._open_alert(None, position)
                break

    def _open_alert(self, _list, position):
        if position >= len(self.alerts):
            return
        _, event, rule, reason = self.alerts[position]
        self._show_socket(event.connection, event=event, alert=(rule, reason))

    def _security_context(self, page, connection, event, alert):
        if alert:
            rule, reason = alert
            group = self._section("Alert evidence", reason)
            self._field(
                group, "Observed at", f"{event.time:%Y-%m-%d %H:%M:%S} · {event.source}"
            )
            key = f"{rule}:{app_key(connection)}"

            def mute(row):
                muted = list(self.settings["muted"])
                if key in muted:
                    muted.remove(key)
                else:
                    muted.append(key)
                self._set("muted", muted)
                row.set_title(
                    "Unmute this rule for this app"
                    if key in muted
                    else "Mute this rule for this app"
                )

            self._button(
                group,
                "Unmute this rule for this app"
                if key in self.settings["muted"]
                else "Mute this rule for this app",
                "Activity and inbox entries remain available",
                mute,
            )
            page.add(group)
        if connection.remote:
            self._ip_context(page, connection.remote.host)
        if event:
            group = self._section("Activity evidence")
            self._field(group, "Direction", direction(event))
            self._field(group, "Observation", event.kind)
            if event.detail:
                self._field(group, "Details", event.detail)
            page.add(group)
        if connection.pid and not self.demo:
            group = self._section("App activity")
            self._button(
                group,
                "Show activity for this app",
                "Search current activity",
                lambda *_: self._find_app(connection),
            )
            if connection.started and not connection.is_listener:
                unit = self._field(group, "Systemd unit", "Checking…")
                self._work(
                    lambda: systemd_unit(connection),
                    lambda value: unit.set_subtitle(value or "Unavailable"),
                )
            if connection.executable or connection.process:
                self._button(
                    group,
                    "Watch destinations for 15 minutes",
                    "New observed peers can trigger an alert",
                    lambda *_: self._watch_app(connection),
                )
            if connection.is_listener and connection.local:
                self._button(
                    group,
                    "Watch this service",
                    "Alert on the first observed TCP accept",
                    lambda *_: self._watch_service(connection),
                )
            page.add(group)
        outbound = event and direction(event) == "Outbound"
        if not self.demo and (connection.is_listener or outbound):
            endpoint = connection.remote if outbound else connection.local
            if endpoint and classify(endpoint.host)[1] != "Loopback":
                group = self._section("Firewall")
                self._button(
                    group,
                    "Block new traffic for 15 minutes",
                    f"{'Outbound destination' if outbound else 'Inbound listener'} · {endpoint}",
                    lambda *_: self._choose_block(connection, bool(outbound)),
                )
                page.add(group)

    def _watch_app(self, connection):
        until = time() + 900
        self.monitor.watches[app_key(connection)] = until
        if not connection.executable:
            self.monitor.watches[connection.process_label] = until
        if self.snapshot:
            for row in self.snapshot.connections:
                if app_key(row) == app_key(connection) and row.remote:
                    self.monitor.seen[
                        ("watch", app_key(row), row.remote, row.protocol)
                    ] = until
        self._toast(f"Watching {connection.process_label} for 15 minutes")

    def _watch_service(self, connection):
        self.monitor.services.add((app_key(connection), connection.local.port))
        self.monitor.services.add((connection.process_label, connection.local.port))
        self._toast(f"Watching TCP port {connection.local.port}")

    def _find_app(self, connection):
        dialog = self.get_visible_dialog()
        if dialog:
            dialog.close()
        self.activity_kind.set_selected(0)
        self.activity_search.set_text(app_key(connection))
        self._activity_changed()
        self.views.set_visible_child_name("activity")

    def _ip_context(self, page, host):
        address, scope = classify(host)
        group = self._section("Inspect IP")
        self._field(group, "Address scope", scope)
        page.add(group)
        if self.demo or scope != "Public address":
            return

        def start(row):
            row.set_sensitive(False)
            row.set_subtitle("Querying the registry and RIPEstat…")

            def done(values):
                row.set_subtitle("RDAP, RIPEstat and reverse DNS")
                for title, value in values:
                    if title == "Announced prefix" and value != "Unavailable":
                        self._button(
                            group,
                            f"Observed connections in {value}",
                            "Group by application",
                            lambda *_, prefix=value: self._network_activity(prefix),
                        )
                    self._field(group, title, value)

            self._work(
                lambda: lookup(str(address)),
                done,
                lambda _error: row.set_subtitle("Lookup unavailable"),
            )

        self._button(
            group,
            "Look Up IP",
            "Send this public IP to RDAP, RIPEstat and your DNS resolver",
            start,
        )

    def _network_activity(self, prefix):
        try:
            network = ip_network(prefix)
        except ValueError:
            return
        self._grouped_activity(network)

    def _grouped_activity(self, network=None):
        groups = defaultdict(dict)
        for row in self.activity_store if network else self.activity_model:
            event = row.event
            connection = event.connection
            if not connection:
                continue
            peer = connection.remote
            if network and (not peer or classify(peer.host)[0] not in network):
                continue
            key = (direction(event), peer or connection.local, connection.protocol)
            groups[app_key(connection)].setdefault(key, event)
        page = Adw.PreferencesPage()
        for app, peers in sorted(groups.items()):
            group = self._section(app)
            for (flow, endpoint, protocol), event in peers.items():
                self._button(
                    group,
                    f"{endpoint} · {protocol}",
                    flow,
                    lambda *_, match=event: self._show_socket(
                        match.connection, event=match
                    ),
                )
            page.add(group)
        if not groups:
            page.add(
                self._section(
                    "No matching activity",
                    "Only retained activity from this run is shown.",
                )
            )
        self._dialog(f"Activity in {network}" if network else "Activity by App", page)

    def _choose_block(self, connection, outbound):
        def show(choices):
            if not choices:
                self._toast(
                    "No active host-output policy"
                    if outbound
                    else "No active firewalld zone"
                )
                return
            target = self._dropdown(
                choices, "Firewall policy" if outbound else "Firewall zone"
            )
            endpoint = connection.remote if outbound else connection.local
            scope = (
                f"all {connection.family} addresses on port {endpoint.port}"
                if not outbound and connection.is_wildcard
                else str(endpoint)
            )
            dialog = Adw.AlertDialog(
                heading="Block new traffic for 15 minutes?",
                body=f"{'Outbound destination' if outbound else 'Inbound destination'} {scope} "
                f"over {connection.protocol}. The rule applies to all apps in the selected "
                f"{'policy' if outbound else 'zone'}. Existing connections may stay open.",
                extra_child=target,
            )
            dialog.add_response("cancel", "Cancel")
            dialog.add_response("block", "Block")
            dialog.set_close_response("cancel")
            dialog.set_response_appearance("block", Adw.ResponseAppearance.DESTRUCTIVE)

            def respond(_dialog, response):
                if response == "block":
                    self._apply_block(
                        connection, outbound, choices[target.get_selected()]
                    )

            dialog.connect("response", respond)
            dialog.present(self)

        self._work(
            lambda: firewall.targets(outbound),
            show,
            lambda error: self._toast(f"Firewall unavailable · {error[-150:]}"),
        )

    def _apply_block(self, connection, outbound, target):
        try:
            token, rule = firewall.make_rule(connection, outbound)
        except ValueError as error:
            self._toast(str(error))
            return

        def applied(_result):
            self.blocks[token] = (target, rule, outbound, time() + firewall.TIMEOUT)
            toast = Adw.Toast(
                title=f"Temporary block added in {target}",
                button_label="Undo",
                timeout=10,
            )
            toast.connect("button-clicked", lambda *_: self._undo_block(token))
            self.toasts.add_toast(toast)

        self._work(
            lambda: firewall.change(target, rule, outbound),
            applied,
            lambda error: self._toast(
                f"Firewall rule could not be added · {error[-150:]}"
            ),
        )

    def _undo_block(self, token, done=None):
        target, rule, outbound, _expires = self.blocks[token]

        def removed(_result):
            self.blocks.pop(token, None)
            self._toast("Temporary block removed")
            if done:
                done()

        self._work(
            lambda: firewall.change(target, rule, outbound, remove=True),
            removed,
            lambda error: self._toast(f"Couldn’t remove rule · {error[-150:]}"),
        )

    def _show_blocks(self, *_):
        page = Adw.PreferencesPage()
        group = self._section(
            "Runtime rules", "Rules expire after 15 minutes or when firewalld reloads."
        )
        page.add(group)
        dialog = self._dialog("Temporary Firewall Blocks", page)
        for token, (target, rule, outbound, expires) in self.blocks.items():
            if expires > time():
                title = f"{'Outbound' if outbound else 'Inbound'} · {target} · {datetime.fromtimestamp(expires):%H:%M}"
                row = self._button(
                    group,
                    title,
                    rule,
                    lambda _row, t=token: self._undo_block(t, dialog.close),
                )
                row.set_subtitle_lines(3)
        if not any(item[3] > time() for item in self.blocks.values()):
            group.set_description("No temporary rules added in this run.")

    def _read_firewall(self):
        if self.demo or self.firewall_busy:
            return
        self.firewall_busy = True
        args = ["journalctl", "-k", "-b", "--no-pager", "-o", "json", "--grep=^SF-"]
        if self.firewall_cursor:
            args.append(f"--after-cursor={self.firewall_cursor}")
        else:
            args.append(f"--since=@{int(self.firewall_started)}")

        def read():
            result = subprocess.run(
                args,
                check=False,
                capture_output=True,
                text=True,
                errors="replace",
                timeout=3,
            )
            if result.returncode not in (0, 1) or any(
                text in result.stderr.casefold()
                for text in ("permission", "not seeing messages", "no journal")
            ):
                raise ValueError("Kernel journal unavailable")
            records = [json.loads(line) for line in result.stdout.splitlines()]
            return records

        def apply(records):
            self.firewall_busy = False
            self.firewall_status = "SocketForge rules · rate-limited journal entries"
            events = []
            for record in records:
                self.firewall_cursor = record.get("__CURSOR", self.firewall_cursor)
                message = record.get("MESSAGE")
                event = (
                    firewall.parse_hit(message) if isinstance(message, str) else None
                )
                if event:
                    stamp = record.get("__REALTIME_TIMESTAMP")
                    if stamp and stamp.isdigit():
                        event = type(event)(
                            datetime.fromtimestamp(int(stamp) / 1e6).astimezone(),
                            event.kind,
                            event.connection,
                            event.detail,
                            event.source,
                        )
                    events.append(event)
            self._record(events)
            if self.session and self.session.active:
                relevant = [
                    event for event in events if event.time >= self.session_started_at
                ]
                if relevant:
                    self.session.add(*relevant)
                    self._update_session()
            self._refresh_activity_status()

        def failed(_error):
            self.firewall_busy = False
            self.firewall_status = "Kernel journal unavailable"
            self._refresh_activity_status()

        self._work(read, apply, failed)

    def _read_host(self):
        if self.demo or self.host_busy:
            return
        self.host_busy = True

        def apply(result):
            self.host_busy = False
            self.host_cursor, events, active = result
            if active != self.host_state and self.host_state - active:
                events.append(
                    Event(
                        datetime.now().astimezone(),
                        "Host collector stopped",
                        detail=", ".join(sorted(self.host_state - active)),
                        source="Host collector",
                    )
                )
            self.host_state = active
            self.host_label = (
                "Host services: " + ", ".join(sorted(active)) if active else ""
            )
            self._record(events)
            if self.session and self.session.active:
                matching = [
                    event for event in events if event.time >= self.session_started_at
                ]
                if matching:
                    self.session.add(*matching)
                    self._update_session()
            self._refresh_activity_status()

        def failed(_error):
            self.host_busy = False
            self.host_label = "Host collector journal unavailable"
            self._refresh_activity_status()

        self._work(
            lambda: host.read(self.host_cursor, self.firewall_started), apply, failed
        )
