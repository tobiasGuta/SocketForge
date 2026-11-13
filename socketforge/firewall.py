"""Scoped runtime firewalld rules and rate-limited hit decoding."""

import ipaddress
import re
import subprocess
from datetime import datetime
from uuid import uuid4

from .network import Connection, Endpoint
from .timeline import Event

TIMEOUT = 900
PREFIX = "SF-"
FIREWALL = "/usr/bin/firewall-cmd"


def query(*args, timeout=5):
    return subprocess.run(
        [FIREWALL, *args],
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        check=True,
        timeout=timeout,
    ).stdout.strip()


def targets(outbound):
    if not outbound:
        return [
            line.split()[0]
            for line in query("--get-active-zones").splitlines()
            if line and not line[0].isspace()
        ]
    choices = []
    for name in query("--get-active-policies").splitlines():
        if name and not name[0].isspace():
            ingress = query(f"--policy={name}", "--list-ingress-zones").split()
            egress = query(f"--policy={name}", "--list-egress-zones").split()
            if ingress == ["HOST"] and egress and "HOST" not in egress:
                choices.append(name)
    return choices


def make_rule(connection, outbound):
    endpoint = connection.remote if outbound else connection.local
    if endpoint is None or not 1 <= endpoint.port <= 65535:
        raise ValueError("A valid endpoint is required")
    address = ipaddress.ip_address(endpoint.host.split("%")[0])
    address = getattr(address, "ipv4_mapped", None) or address
    if (
        address.is_loopback
        or address.is_multicast
        or (outbound and address.is_unspecified)
    ):
        raise ValueError("This address is outside the supported block scope")
    protocol = connection.protocol.lower()
    if protocol not in ("tcp", "udp"):
        raise ValueError("Unsupported protocol")
    token = PREFIX + uuid4().hex[:12]
    match = (
        f' destination address="{address}"'
        if outbound or not address.is_unspecified
        else ""
    )
    rule = (
        f'rule family="ipv{address.version}" priority="-100"{match}'
        f' port port="{endpoint.port}" protocol="{protocol}"'
        f' log prefix="{token} " limit value="6/m" reject'
    )
    return token, rule


def change(target, rule, outbound, remove=False):
    if not re.fullmatch(r"[A-Za-z0-9_-]+", target):
        raise ValueError("Invalid firewall zone or policy")
    selector = f"--policy={target}" if outbound else f"--zone={target}"
    if not remove and target not in targets(outbound):
        raise ValueError("The selected firewall zone or policy is no longer active")
    operation = f"--remove-rich-rule={rule}" if remove else f"--add-rich-rule={rule}"
    query(
        selector, operation, *(() if remove else (f"--timeout={TIMEOUT}",)), timeout=90
    )


def parse_hit(message):
    hit = re.match(r"^(SF-[a-f0-9]{12})\s+.*?\bSRC=", message)
    if not hit:
        return None
    fields = dict(re.findall(r"\b([A-Z]+)=(\S*)", message))
    try:
        src, dst = (ipaddress.ip_address(fields[key]) for key in ("SRC", "DST"))
        sport, dport = (int(fields[key]) for key in ("SPT", "DPT"))
        protocol = fields["PROTO"].upper()
        if (
            src.version != dst.version
            or not (0 <= sport <= 65535 and 0 <= dport <= 65535)
            or protocol not in ("TCP", "UDP")
        ):
            return None
    except (KeyError, ValueError):
        return None
    outgoing = not fields.get("IN") and bool(fields.get("OUT"))
    local, remote = (Endpoint(str(src), sport), Endpoint(str(dst), dport))
    if not outgoing:
        local, remote = remote, local
    row = Connection(
        None, None, None, protocol, f"IPv{src.version}", local, remote, None
    )
    return Event(
        datetime.now().astimezone(),
        "Firewall rule hit",
        row,
        f"{hit[1]} · {src}:{sport} → {dst}:{dport}",
        "Firewall",
    )
