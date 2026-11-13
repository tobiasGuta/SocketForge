"""Compare visible socket snapshots and keep optional local session history."""

import json
import os
import sqlite3
from collections import defaultdict, deque
from contextlib import closing
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from pathlib import Path
from uuid import uuid4

from .network import Connection, Endpoint

MAX_EVENTS = 2000
RETENTION_DAYS = 7


@dataclass(frozen=True)
class Event:
    time: datetime
    kind: str
    connection: Connection | None = None
    detail: str = ""
    source: str = "Snapshot"


def identity(connection):
    if connection.inode:
        return (
            "inode",
            connection.inode,
            connection.protocol,
            connection.family,
            connection.local,
            connection.remote,
        )
    return (
        "endpoint",
        connection.pid,
        connection.started,
        connection.protocol,
        connection.family,
        connection.local,
        connection.remote,
    )


def index(snapshot):
    rows = defaultdict(list)
    for connection in snapshot.connections:
        rows[identity(connection)].append(connection)
    return rows


class Session:
    def __init__(self, persist=False):
        self.id = uuid4().hex
        self.events = deque(maxlen=MAX_EVENTS)
        self.previous = None
        self.last_snapshot_at = None
        self.last_seen = {}
        self.event_count = 0
        self.active = True
        self.persist = persist

    def add(self, *events):
        self.events.extend(events)
        self.event_count += len(events)

    def gap(self, now, reason):
        if self.previous is None:
            return
        self.add(Event(now, "Observation gap", detail=reason))
        self.previous = None
        self.last_snapshot_at = None
        self.last_seen.clear()

    def observe(self, snapshot):
        now = snapshot.captured_at
        current = index(snapshot)
        if self.previous is None:
            self.add(
                Event(
                    now,
                    "Baseline captured",
                    detail=f"{len(snapshot.connections):,} visible sockets",
                )
            )
        else:
            changes = []
            for key in self.previous.keys() | current.keys():
                before = self.previous.get(key, [])
                after = current.get(key, [])
                pairs = []
                for old in before:
                    match = next((row for row in after if row.state == old.state), None)
                    if match is None:
                        pairs.append(old)
                    else:
                        after = list(after)
                        after.remove(match)
                for old, new in zip(pairs, after):
                    changes.append(
                        Event(
                            now,
                            "TCP state changed",
                            new,
                            f"{old.state or '—'} → {new.state or '—'}",
                        )
                    )
                for old in pairs[len(after) :]:
                    kind = (
                        "Listener last seen" if old.is_listener else "Socket last seen"
                    )
                    changes.append(Event(self.last_seen[key], kind, old))
                for new in after[len(pairs) :]:
                    kind = (
                        "Listener first seen"
                        if new.is_listener
                        else "Socket first seen"
                    )
                    changes.append(Event(now, kind, new))
            self.add(
                *sorted(
                    changes,
                    key=lambda event: (
                        event.time,
                        event.kind,
                        event.connection.search_text,
                    ),
                )
            )
        self.previous = current
        self.last_snapshot_at = now
        self.last_seen = dict.fromkeys(current, now)


def _history():
    base = Path(os.environ.get("XDG_STATE_HOME") or Path.home() / ".local/state")
    directory = base / "socketforge"
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    database = directory / "history.sqlite3"
    fd = os.open(database, os.O_CREAT | os.O_WRONLY, 0o600)
    os.close(fd)
    return sqlite3.connect(database)


def _prepare(db):
    db.execute(
        "CREATE TABLE IF NOT EXISTS sessions (id TEXT PRIMARY KEY, saved TEXT, events TEXT)"
    )
    cutoff = (datetime.now().astimezone() - timedelta(days=RETENTION_DAYS)).timestamp()
    db.execute("DELETE FROM sessions WHERE CAST(saved AS REAL) < ?", (cutoff,))


def save(session):
    records = []
    for event in session.events:
        record = asdict(event)
        record["time"] = event.time.isoformat()
        records.append(record)
    with closing(_history()) as db, db:
        _prepare(db)
        db.execute(
            "INSERT OR REPLACE INTO sessions VALUES (?, ?, ?)",
            (session.id, datetime.now().timestamp(), json.dumps(records)),
        )
        db.execute(
            "DELETE FROM sessions WHERE id NOT IN "
            "(SELECT id FROM sessions ORDER BY CAST(saved AS REAL) DESC LIMIT 20)"
        )


def load_recent():
    with closing(_history()) as db, db:
        _prepare(db)
        rows = db.execute(
            "SELECT saved, events FROM sessions ORDER BY CAST(saved AS REAL) DESC"
        ).fetchall()
    sessions = []
    for saved, records in rows:
        events = []
        for record in json.loads(records):
            connection = record.pop("connection")
            if connection:
                for field in ("local", "remote"):
                    if connection[field]:
                        connection[field] = Endpoint(**connection[field])
                connection = Connection(**connection)
            events.append(
                Event(
                    datetime.fromisoformat(record.pop("time")),
                    connection=connection,
                    **record,
                )
            )
        sessions.append((datetime.fromtimestamp(float(saved)).astimezone(), events))
    return sessions


def clear_history():
    with closing(_history()) as db, db:
        _prepare(db)
        db.execute("DELETE FROM sessions")
