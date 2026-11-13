"""Read opt-in host collector records from the system journal."""

import json
import subprocess
from datetime import datetime

import psutil

from .timeline import Event
from .trace import parse, parse_udp

UNITS = ("socketforge-tcp.service", "socketforge-udp.service")


def read(cursor, started):
    state = subprocess.run(
        ["/usr/bin/systemctl", "show", "--property=Id,ActiveState", *UNITS],
        check=True,
        capture_output=True,
        text=True,
        timeout=3,
    )
    active = {
        group["Id"].split("-")[1].split(".")[0].upper()
        for block in state.stdout.strip().split("\n\n")
        if (
            group := dict(
                line.split("=", 1) for line in block.splitlines() if "=" in line
            )
        )
        and group.get("Id") in UNITS
        and group.get("ActiveState") == "active"
    }
    if not active and cursor is None:
        return cursor, [], active
    start = f"--after-cursor={cursor}" if cursor else f"--since=@{int(started)}"
    result = subprocess.run(
        [
            "/usr/bin/journalctl",
            "-b",
            "--no-pager",
            "-o",
            "json",
            start,
            *(f"--unit={unit}" for unit in UNITS),
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=4,
    )
    if (
        "permission" in result.stderr.casefold()
        or "not seeing messages" in result.stderr.casefold()
    ):
        raise ValueError("Host journal unavailable")
    addresses = {
        address.address.split("%")[0]
        for items in psutil.net_if_addrs().values()
        for address in items
    }
    events = []
    for line in result.stdout.splitlines():
        record = json.loads(line)
        cursor = record.get("__CURSOR", cursor)
        unit = record.get("_SYSTEMD_UNIT")
        message = record.get("MESSAGE")
        if unit not in UNITS or not isinstance(message, str):
            continue
        event = parse(message) if unit == UNITS[0] else parse_udp(message, addresses)
        if event:
            stamp = datetime.fromtimestamp(
                int(record["__REALTIME_TIMESTAMP"]) / 1e6
            ).astimezone()
            events.append(
                Event(
                    stamp,
                    event.kind,
                    event.connection,
                    event.detail,
                    "Host TCP trace" if unit == UNITS[0] else event.source,
                )
            )
        elif any(
            word in message.casefold()
            for word in ("failed", "no buffer space", "overrun")
        ):
            stamp = datetime.fromtimestamp(
                int(record["__REALTIME_TIMESTAMP"]) / 1e6
            ).astimezone()
            events.append(
                Event(
                    stamp,
                    "Collector gap",
                    detail=message[:180],
                    source="Host collector",
                )
            )
    return cursor, events, active
