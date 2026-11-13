"""Read metadata from Fedora's BCC tcptracer on a dedicated input stream."""

import ipaddress
import re
from datetime import datetime
from queue import Empty, Full, Queue
from threading import Thread

from .network import Connection, Endpoint
from .timeline import Event

EVENTS = {"C": "TCP connected", "A": "TCP accepted", "X": "TCP closed"}
ROW = re.compile(r"([CAX])\s+(\d+)\s+(.*?)\s+([46])\s+(\S+)\s+(\S+)\s+(\d+)\s+(\d+)")


def parse(line):
    now = datetime.now().astimezone()
    if "lost" in line.casefold() and any(
        word in line.casefold() for word in ("event", "sample")
    ):
        return Event(
            now, "Trace event loss", detail=line.strip()[:180], source="Kernel trace"
        )
    match = ROW.fullmatch(line.strip())
    if match is None:
        return None
    kind, pid, process, version, local, remote, local_port, remote_port = match.groups()
    try:
        addresses = [
            ipaddress.ip_address(value.strip("[]")) for value in (local, remote)
        ]
    except ValueError:
        return None
    if any(address.version != int(version) for address in addresses):
        return None
    if max(int(local_port), int(remote_port)) > 65535:
        return None
    row = Connection(
        process.strip() or None,
        int(pid) or None,
        None,
        "TCP",
        f"IPv{version}",
        Endpoint(str(addresses[0]), int(local_port)),
        Endpoint(str(addresses[1]), int(remote_port)),
        None,
    )
    return Event(now, EVENTS[kind], row, source="Kernel trace")


class TraceInput:
    def __init__(self, stream):
        self.events = Queue(maxsize=4096)
        self.status = "Waiting for the TCP collector"
        self.dropped = 0
        Thread(
            target=self._read, args=(stream,), name="trace-input", daemon=True
        ).start()

    def _read(self, stream):
        last_message = ""
        for line in stream:
            if line.startswith("Tracing TCP established") or line.split() == [
                "T",
                "PID",
                "COMM",
                "IP",
                "SADDR",
                "DADDR",
                "SPORT",
                "DPORT",
            ]:
                self.status = "Kernel trace connected"
                continue
            event = parse(line)
            if event is None:
                if line.strip():
                    last_message = line.strip()[:180]
                continue
            try:
                self.events.put_nowait(event)
            except Full:
                self.dropped += 1
        self.status = f"Trace ended · {last_message}" if last_message else "Trace ended"

    def drain(self):
        events = []
        for _ in range(4096):
            try:
                events.append(self.events.get_nowait())
            except Empty:
                break
        return events
