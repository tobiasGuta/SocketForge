"""Activity classification and local alert rules."""

from collections import OrderedDict
from datetime import datetime
from time import time

from .intelligence import classify
from .timeline import Event, Session

ACTIVITY_KINDS = (
    "All activity",
    "Outbound",
    "Inbound",
    "Listening",
    "Blocked",
    "Unknown",
)


def direction(event):
    if event.kind in ("TCP connected", "UDP outbound flow"):
        return "Outbound"
    if event.kind in ("TCP accepted", "UDP inbound flow"):
        return "Inbound"
    if event.source == "Firewall":
        return "Blocked"
    if event.connection and event.connection.is_listener:
        return "Listening"
    return "Unknown"


def app_key(connection):
    return connection.executable or connection.process_label


class Monitor:
    def __init__(self):
        self.session = Session()
        self.cursor = 0
        self.watches = {}
        self.seen = OrderedDict()
        self.services = set()

    def gap(self, reason):
        self.session.gap(datetime.now().astimezone(), reason)

    def snapshot(self, snapshot):
        initial = self.session.previous is None
        self.session.observe(snapshot)
        events = (
            list(self.session.events)[
                -min(self.session.event_count - self.cursor, len(self.session.events)) :
            ]
            if self.session.event_count > self.cursor
            else []
        )
        self.cursor = self.session.event_count
        if initial:
            events.extend(
                Event(
                    snapshot.captured_at,
                    "Listener at baseline"
                    if connection.is_listener
                    else "Socket at baseline",
                    connection,
                )
                for connection in snapshot.connections
            )
        return events

    def alert(self, event):
        row = event.connection
        if row is None:
            return None
        app = app_key(row)
        reason = None
        if (
            event.kind == "Listener first seen"
            and row.local
            and classify(row.local.host)[1] != "Loopback"
        ):
            key = ("listener", app, row.local)
            reason = "New non-loopback TCP listener"
        elif (
            event.kind == "TCP accepted"
            and row.local
            and (
                (app, row.local.port) in self.services
                or (row.process_label, row.local.port) in self.services
            )
        ):
            key = ("inbound", app, row.local.port)
            reason = "First inbound connection to a watched service"
        elif (
            event.kind in ("TCP connected", "Socket first seen")
            and row.remote
            and max(self.watches.get(app, 0), self.watches.get(row.process_label, 0))
            > time()
        ):
            key = ("watch", app, row.remote, row.protocol)
            reason = "New destination for a watched app"
        elif event.source == "Firewall":
            key = ("firewall", event.detail.split()[0])
            reason = "First recorded hit on a SocketForge firewall rule"
        if reason is None:
            return None
        until = self.seen.get(key, 0)
        if until > time():
            return None
        self.seen[key] = (
            max(self.watches.get(app, 0), self.watches.get(row.process_label, 0))
            if key[0] == "watch"
            else time() + 3600
        )
        self.seen.move_to_end(key)
        if len(self.seen) > 4096:
            self.seen.popitem(last=False)
        return key[0], reason
