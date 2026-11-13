import os
import socket
import tempfile
import unittest
from dataclasses import replace
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import patch

from socketforge.diagnostics import rates
from socketforge.network import Connection, Endpoint, Snapshot, collect
from socketforge.timeline import Session, clear_history, load_recent, save
from socketforge.trace import parse


class SessionTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime.now().astimezone()
        self.listener = Connection(
            "python3",
            123,
            "/usr/bin/python3",
            "TCP",
            "IPv4",
            Endpoint("127.0.0.1", 8080),
            None,
            "LISTEN",
            inode=42,
        )

    def test_listener_survives_removal_and_persistence(self):
        session = Session(persist=True)
        session.observe(Snapshot((), self.now))
        first_seen = self.now + timedelta(seconds=2)
        session.observe(Snapshot((self.listener,), first_seen))
        session.observe(Snapshot((), self.now + timedelta(seconds=4)))
        events = list(session.events)
        self.assertEqual(
            [event.kind for event in events],
            ["Baseline captured", "Listener first seen", "Listener last seen"],
        )
        self.assertEqual(events[2].time, first_seen)
        self.assertEqual(events[2].connection, self.listener)
        with (
            tempfile.TemporaryDirectory() as directory,
            patch.dict(os.environ, {"XDG_STATE_HOME": directory}),
        ):
            save(session)
            self.assertEqual(load_recent()[0][1], events)
            database = Path(directory, "socketforge/history.sqlite3")
            self.assertEqual(database.stat().st_mode & 0o777, 0o600)
            clear_history()
            self.assertEqual(load_recent(), [])

    def test_gap_does_not_turn_missing_samples_into_socket_events(self):
        session = Session()
        session.observe(Snapshot((self.listener,), self.now))
        session.gap(self.now + timedelta(seconds=2), "Snapshot read failed")
        session.observe(Snapshot((), self.now + timedelta(seconds=4)))
        self.assertEqual(
            [event.kind for event in session.events],
            ["Baseline captured", "Observation gap", "Baseline captured"],
        )

    def test_state_change_uses_same_socket_identity(self):
        session = Session()
        row = replace(
            self.listener, remote=Endpoint("192.0.2.1", 443), state="SYN_SENT"
        )
        session.observe(Snapshot((row,), self.now))
        session.observe(Snapshot((replace(row, state="ESTABLISHED"),), self.now))
        self.assertEqual(session.events[-1].detail, "SYN_SENT → ESTABLISHED")


class DiagnosticsTests(unittest.TestCase):
    def test_live_tcp_info_follows_the_socket(self):
        with socket.socket() as server:
            server.bind(("127.0.0.1", 0))
            server.listen()
            with (
                socket.create_connection(server.getsockname()) as client,
                server.accept()[0] as peer,
            ):

                def sample():
                    snapshot = collect()
                    connection = next(
                        row
                        for row in snapshot.connections
                        if row.pid == os.getpid()
                        and row.local.port == server.getsockname()[1]
                        and row.state == "ESTABLISHED"
                    )
                    return snapshot.diagnostics.sockets[connection.inode]

                before = sample()
                client.sendall(b"a" * 8192)
                self.assertEqual(len(peer.recv(8192, socket.MSG_WAITALL)), 8192)
                after = sample()
                self.assertEqual(after.received - before.received, 8192)
                self.assertEqual(rates(after, before, 2)[1], 4096)
                self.assertIsNone(rates(after, replace(before, cookie=b"another"), 2))


class TraceTests(unittest.TestCase):
    def test_fedora_ipv6_and_loss_messages(self):
        event = parse("A 204 worker thread 6 [::1] [::1] 8080 40000")
        self.assertEqual(event.kind, "TCP accepted")
        self.assertEqual(event.connection.process, "worker thread")
        self.assertEqual(str(event.connection.local), "[::1]:8080")
        self.assertEqual(parse("Possibly lost 12 samples").kind, "Trace event loss")
        self.assertIsNone(parse("header line"))
