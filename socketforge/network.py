"""Read an unprivileged snapshot of local IPv4 and IPv6 sockets."""

import os
import socket
import time
from dataclasses import dataclass
from datetime import datetime

import psutil

from .diagnostics import Diagnostics, collect_tcp


@dataclass(frozen=True, order=True)
class Endpoint:
    host: str
    port: int

    def __str__(self):
        if ":" in self.host:
            return f"[{self.host}]:{self.port}"
        return f"{self.host}:{self.port}"


@dataclass(frozen=True)
class Connection:
    process: str | None
    pid: int | None
    executable: str | None
    protocol: str
    family: str
    local: Endpoint | None
    remote: Endpoint | None
    state: str | None
    started: float | None = None
    inode: int | None = None
    parent: str | None = None

    @property
    def process_label(self):
        if self.process:
            return self.process
        return f"PID {self.pid}" if self.pid is not None else "Unknown process"

    def owner_explanation(self, source=None):
        if self.process:
            return None
        if self.pid is not None:
            return "The socket has a PID. The process name was unavailable when it was read."
        if source in ("Firewall", "Host conntrack"):
            return "This network record contains endpoints and protocol without a process ID."
        if self.state == "TIME_WAIT":
            return "Linux can keep this TCP entry after the connection closes and the process releases the socket."
        if source in ("Kernel trace", "Host TCP trace"):
            return "The TCP trace did not report a process for this event."
        return (
            "Linux reported the socket without a readable owning PID. Another user, "
            "an exited process, or a kernel-managed socket can account for this."
        )

    @property
    def is_listener(self):
        return self.protocol == "TCP" and self.state == "LISTEN"

    @property
    def is_bound_udp(self):
        return self.protocol == "UDP" and self.local is not None and self.remote is None

    @property
    def is_wildcard(self):
        return self.local is not None and self.local.host in ("0.0.0.0", "::")

    @property
    def search_text(self):
        return " ".join(
            str(value)
            for value in (
                self.process_label,
                self.pid,
                self.executable,
                self.protocol,
                self.family,
                self.local,
                self.remote,
                self.state,
            )
            if value is not None
        ).casefold()


@dataclass(frozen=True)
class Snapshot:
    connections: tuple[Connection, ...]
    captured_at: datetime
    diagnostics: Diagnostics | None = None

    @property
    def listener_count(self):
        return sum(connection.is_listener for connection in self.connections)

    @property
    def process_count(self):
        return len({row.pid for row in self.connections if row.pid is not None})


def _process_details(pid, collection_started):
    try:
        process = psutil.Process(pid)
        with process.oneshot():
            started = process.create_time()
            if started > collection_started:
                return None, None, None, None
            name = process.name()
            try:
                parent_process = process.parent()
                parent = (
                    f"{parent_process.name()} · PID {parent_process.pid}"
                    if parent_process
                    else None
                )
            except psutil.Error:
                parent = None
            try:
                return name, process.exe() or None, started, parent
            except psutil.Error:
                return name, None, started, parent
    except psutil.Error:
        return None, None, None, None


def _socket_inode(pid, fd):
    if pid is None or fd < 0:
        return None
    try:
        target = os.readlink(f"/proc/{pid}/fd/{fd}")
        if target.startswith("socket:[") and target.endswith("]"):
            return int(target[8:-1])
    except (OSError, ValueError):
        pass
    return None


def _display_text(value):
    if value is None:
        return None
    # Linux process names and paths can contain bytes outside UTF-8.
    return value.encode("utf-8", errors="surrogateescape").decode(
        "utf-8", errors="replace"
    )


def collect():
    collection_started = time.time()
    sockets = psutil.net_connections(kind="inet")
    captured_at = datetime.now().astimezone()
    processes = {}
    connections = []
    for sock in sockets:
        if sock.pid is not None and sock.pid not in processes:
            processes[sock.pid] = _process_details(sock.pid, collection_started)
        name, executable, started, parent = processes.get(
            sock.pid, (None, None, None, None)
        )
        # psutil 8 uses enum values. Earlier versions expose state as a string.
        state = getattr(sock.status, "value", sock.status)
        connections.append(
            Connection(
                process=_display_text(name),
                pid=sock.pid,
                executable=_display_text(executable),
                protocol="TCP" if sock.type == socket.SOCK_STREAM else "UDP",
                family="IPv6" if sock.family == socket.AF_INET6 else "IPv4",
                local=Endpoint(*sock.laddr) if sock.laddr else None,
                remote=Endpoint(*sock.raddr) if sock.raddr else None,
                state=None if state == "NONE" else state,
                started=started,
                parent=_display_text(parent),
                inode=_socket_inode(sock.pid, sock.fd) if started is not None else None,
            )
        )

    connections.sort(
        key=lambda row: (
            row.pid if row.pid is not None else -1,
            row.protocol,
            row.family,
            row.local or Endpoint("", 0),
            row.remote or Endpoint("", 0),
            row.state or "",
            row.inode or 0,
        )
    )
    try:
        diagnostics = collect_tcp()
    except OSError:
        diagnostics = None
    return Snapshot(tuple(connections), captured_at, diagnostics)
