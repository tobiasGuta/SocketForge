"""Read local service, firewall and container context for a TCP listener."""

import ipaddress
import re
import subprocess

import psutil


def _query(*command):
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=1.5,
            check=True,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    return result.stdout.strip()


def systemd_unit(connection):
    if connection.pid is None or connection.started is None:
        return None
    for bus in ("--user", "--system"):
        try:
            if psutil.Process(connection.pid).create_time() != connection.started:
                return None
        except psutil.Error:
            return None
        object_path = _query(
            "/usr/bin/busctl",
            bus,
            "call",
            "org.freedesktop.systemd1",
            "/org/freedesktop/systemd1",
            "org.freedesktop.systemd1.Manager",
            "GetUnitByPID",
            "u",
            str(connection.pid),
        )
        match = re.fullmatch(
            r'o "(/org/freedesktop/systemd1/unit/[A-Za-z0-9_]+)"', object_path
        )
        if match:
            unit = _query(
                "/usr/bin/busctl",
                bus,
                "get-property",
                "org.freedesktop.systemd1",
                match[1],
                "org.freedesktop.systemd1.Unit",
                "Id",
            )
            if unit.startswith('s "'):
                return unit[3:-1]
    return None


def _firewall_zones(host):
    interfaces = {
        interface
        for interface, addresses in psutil.net_if_addrs().items()
        if any(address.address.split("%")[0] == host for address in addresses)
    }
    lines = _query("/usr/bin/firewall-cmd", "--get-active-zones").splitlines()
    zones = []
    zone = None
    for line in lines:
        if line and not line[0].isspace():
            zone = line.split()[0]
        elif zone and line.strip().startswith("interfaces:"):
            matched = [
                name
                for name in line.split()[1:]
                if name in interfaces or host in ("0.0.0.0", "::")
            ]
            if matched:
                zones.append(f"{zone} ({', '.join(matched)})")
    return "\n".join(zones) or None


def _podman_mappings(host, port):
    output = _query("/usr/bin/podman", "port", "--all")
    matches = []
    for line in output.splitlines():
        match = re.fullmatch(r"(\S+)\s+(\d+)/tcp\s+->\s+(.+):(\d+)", line)
        if match and int(match[4]) == port and match[3].strip("[]") == host:
            name = (
                _query(
                    "/usr/bin/podman",
                    "inspect",
                    "--type",
                    "container",
                    "--format",
                    "{{.Name}}",
                    match[1],
                )
                or match[1][:12]
            )
            matches.append(f"{name} · {match[2]}/tcp → {match[3]}:{port}")
    return "\n".join(matches) or None


def inspect_listener(connection):
    host = connection.local.host
    if connection.is_wildcard:
        bind = f"All {connection.family} interfaces"
    elif ipaddress.ip_address(host).is_loopback:
        bind = "Loopback"
    else:
        bind = "Specific local address"
    return (
        ("Bind scope", bind),
        ("Systemd unit", systemd_unit(connection)),
        ("Podman port mapping", _podman_mappings(host, connection.local.port)),
        ("firewalld interface zones", _firewall_zones(host)),
    )
