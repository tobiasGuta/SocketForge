import unittest
from dataclasses import replace
from datetime import datetime
from time import time
from unittest.mock import patch

from socketforge.firewall import make_rule, parse_hit
from socketforge.intelligence import classify, lookup
from socketforge.network import Connection, Endpoint, Snapshot
from socketforge.security import Monitor, app_key, direction
from socketforge.timeline import Event
from socketforge.trace import parse_udp


class SecurityTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime.now().astimezone()
        self.listener = Connection(
            "python3",
            123,
            "/usr/bin/python3",
            "TCP",
            "IPv4",
            Endpoint("0.0.0.0", 8080),
            None,
            "LISTEN",
        )

    def test_listener_alerts_after_baseline_and_deduplicates(self):
        monitor = Monitor()
        baseline = monitor.snapshot(Snapshot((self.listener,), self.now))
        self.assertTrue(all(monitor.alert(event) is None for event in baseline))
        fresh = replace(self.listener, local=Endpoint("0.0.0.0", 9090))
        events = monitor.snapshot(Snapshot((self.listener, fresh), self.now))
        alert = next(event for event in events if event.kind == "Listener first seen")
        self.assertEqual(monitor.alert(alert)[0], "listener")
        self.assertIsNone(monitor.alert(alert))
        self.assertIsNone(
            monitor.alert(
                replace(
                    alert,
                    connection=replace(
                        fresh,
                        local=Endpoint("::ffff:127.0.0.1", 9090),
                    ),
                )
            )
        )

    def test_watches_and_direction(self):
        monitor = Monitor()
        peer = replace(
            self.listener, remote=Endpoint("192.0.2.1", 443), state="ESTABLISHED"
        )
        event = Event(self.now, "TCP connected", peer)
        self.assertEqual(direction(event), "Outbound")
        self.assertIsNone(monitor.alert(event))
        monitor.watches[app_key(peer)] = time() + 60
        self.assertEqual(monitor.alert(event)[0], "watch")
        self.assertIsNone(monitor.alert(event))
        accepted = replace(event, kind="TCP accepted")
        self.assertEqual(direction(accepted), "Inbound")
        monitor.services.add((app_key(peer), 8080))
        self.assertEqual(monitor.alert(accepted)[0], "inbound")

    def test_firewall_evidence_and_rule_scope(self):
        token, rule = make_rule(self.listener, False)
        self.assertIn('port port="8080" protocol="tcp"', rule)
        self.assertIn('limit value="6/m" reject', rule)
        message = f"{token} IN=wlan0 OUT= SRC=192.0.2.2 DST=192.0.2.3 PROTO=TCP SPT=52400 DPT=8080"
        hit = parse_hit(message)
        self.assertEqual(hit.connection.remote, Endpoint("192.0.2.2", 52400))
        self.assertEqual(direction(hit), "Blocked")
        self.assertIsNone(parse_hit(message.replace("SF-", "OTHER-")))
        _, outbound = make_rule(
            replace(self.listener, remote=Endpoint("2001:db8::5", 443)), True
        )
        self.assertIn('family="ipv6"', outbound)
        self.assertIn('destination address="2001:db8::5"', outbound)

    def test_udp_original_tuple_sets_direction(self):
        message = "[NEW] udp 17 30 src=192.0.2.1 dst=192.0.2.2 sport=55555 dport=53 src=192.0.2.2 dst=192.0.2.1 sport=53 dport=55555"
        self.assertEqual(direction(parse_udp(message, {"192.0.2.1"})), "Outbound")
        self.assertEqual(direction(parse_udp(message, {"192.0.2.2"})), "Inbound")
        self.assertEqual(
            direction(parse_udp(message, {"192.0.2.1", "192.0.2.2"})), "Unknown"
        )
        self.assertIsNone(parse_udp(message, set()))

    def test_special_addresses_do_not_use_online_lookup(self):
        with patch("socketforge.intelligence._lookup") as remote:
            self.assertEqual(
                lookup("192.168.1.2"), (("Address scope", "Private network"),)
            )
            self.assertEqual(classify("2001:db8::1")[1], "Documentation address")
            self.assertEqual(classify("::ffff:127.0.0.1")[1], "Loopback")
            remote.assert_not_called()
