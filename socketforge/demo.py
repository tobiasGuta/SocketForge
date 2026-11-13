"""Fictional socket data for trying the interface without reading host sockets."""

from datetime import datetime

from .network import Connection, Endpoint, Snapshot


def collect_demo():
    rows = [
        (
            "firefox",
            4182,
            "TCP",
            "192.0.2.14",
            42578,
            "203.0.113.10",
            443,
            "ESTABLISHED",
        ),
        (
            "firefox",
            4182,
            "TCP",
            "192.0.2.14",
            42716,
            "198.51.100.33",
            443,
            "ESTABLISHED",
        ),
        ("firefox", 4182, "UDP", "192.0.2.14", 49918, "203.0.113.29", 443, None),
        ("code", 6129, "TCP", "192.0.2.14", 46832, "198.51.100.25", 443, "ESTABLISHED"),
        ("code", 6129, "TCP", "127.0.0.1", 48922, "127.0.0.1", 8080, "ESTABLISHED"),
        ("sshd", 1034, "TCP", "0.0.0.0", 22, None, None, "LISTEN"),
        ("sshd", 1034, "TCP", "::", 22, None, None, "LISTEN"),
        ("python3", 7428, "TCP", "127.0.0.1", 8080, None, None, "LISTEN"),
        ("python3", 7428, "TCP", "192.0.2.14", 58142, "192.0.2.40", 8080, "SYN_SENT"),
        ("avahi-daemon", 980, "UDP", "0.0.0.0", 5353, None, None, None),
        ("avahi-daemon", 980, "UDP", "::", 5353, None, None, None),
        (
            "syncthing",
            5502,
            "TCP",
            "2001:db8::14",
            42038,
            "2001:db8::cafe",
            22000,
            "ESTABLISHED",
        ),
        ("syncthing", 5502, "TCP", "0.0.0.0", 22000, None, None, "LISTEN"),
        (None, None, "TCP", "192.0.2.14", 59408, "203.0.113.81", 443, "TIME_WAIT"),
    ]
    connections = tuple(
        Connection(
            process=name,
            pid=pid,
            executable=f"/usr/bin/{name}" if name else None,
            protocol=protocol,
            family="IPv6" if ":" in local else "IPv4",
            local=Endpoint(local, port),
            remote=Endpoint(remote, remote_port) if remote else None,
            state=state,
        )
        for name, pid, protocol, local, port, remote, remote_port, state in rows
    )
    return Snapshot(connections, datetime.now().astimezone())
