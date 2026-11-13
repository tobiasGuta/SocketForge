"""Read Linux TCP_INFO through the socket diagnostics netlink interface."""

import socket
import struct
from dataclasses import dataclass
from time import monotonic

NETLINK_SOCK_DIAG = 4
SOCK_DIAG_BY_FAMILY = 20
NLM_F_DUMP_INTR = 0x10
NLMSG_HEADER = struct.Struct("=IHHII")
INET_DIAG_REQUEST = struct.Struct("=BBBBI48s")
NLA_HEADER = struct.Struct("=HH")


@dataclass(frozen=True)
class TCPInfo:
    cookie: bytes
    rtt_ms: float
    retransmissions: int
    acked: int
    received: int


@dataclass(frozen=True)
class Diagnostics:
    sampled_at: float
    sockets: dict


def _messages(data):
    offset = 0
    while offset + NLMSG_HEADER.size <= len(data):
        length, kind, flags, _, _ = NLMSG_HEADER.unpack_from(data, offset)
        if length < NLMSG_HEADER.size or offset + length > len(data):
            raise OSError("Malformed socket diagnostic response")
        if flags & NLM_F_DUMP_INTR:
            raise OSError("Interrupted socket diagnostic dump")
        yield kind, data[offset + NLMSG_HEADER.size : offset + length]
        offset += (length + 3) & ~3


def _read_info(data):
    # Linux UAPI inet_diag_msg is 72 bytes. INET_DIAG_INFO carries struct tcp_info.
    if len(data) < 72:
        return None
    inode = struct.unpack_from("=I", data, 68)[0]
    offset = 72
    while inode and offset + NLA_HEADER.size <= len(data):
        length, kind = NLA_HEADER.unpack_from(data, offset)
        if length < NLA_HEADER.size or offset + length > len(data):
            return None
        if kind == 2 and length >= NLA_HEADER.size + 136:
            info = data[offset + NLA_HEADER.size : offset + length]
            # Offsets in include/uapi/linux/tcp.h.
            rtt = struct.unpack_from("=I", info, 68)[0]
            retrans = struct.unpack_from("=I", info, 100)[0]
            acked, received = struct.unpack_from("=QQ", info, 120)
            return inode, TCPInfo(data[44:52], rtt / 1000, retrans, acked, received)
        offset += (length + 3) & ~3
    return None


def collect_tcp():
    result = {}
    for family in (socket.AF_INET, socket.AF_INET6):
        with socket.socket(
            socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_SOCK_DIAG
        ) as netlink:
            netlink.settimeout(0.6)
            request = INET_DIAG_REQUEST.pack(
                family, socket.IPPROTO_TCP, 2, 0, 0xFFFFFFFF, b""
            )
            netlink.sendto(
                NLMSG_HEADER.pack(
                    NLMSG_HEADER.size + len(request), SOCK_DIAG_BY_FAMILY, 0x301, 1, 0
                )
                + request,
                (0, 0),
            )
            while True:
                done = False
                data, _, flags, sender = netlink.recvmsg(256 * 1024)
                if sender[0] != 0 or flags & socket.MSG_TRUNC or not data:
                    raise OSError("Incomplete socket diagnostic response")
                for kind, payload in _messages(data):
                    if kind == 3:  # NLMSG_DONE
                        if len(payload) >= 4 and struct.unpack_from("=i", payload)[0]:
                            raise OSError("Socket diagnostic dump failed")
                        done = True
                    elif kind == 2:  # NLMSG_ERROR
                        raise OSError("Socket diagnostic request failed")
                    elif kind == SOCK_DIAG_BY_FAMILY:
                        info = _read_info(payload)
                        if info:
                            result[info[0]] = info[1]
                if done:
                    break
    return Diagnostics(monotonic(), result)


def rates(info, previous, elapsed):
    if previous is None or info.cookie != previous.cookie or elapsed <= 0:
        return None
    upload = info.acked - previous.acked
    download = info.received - previous.received
    if min(upload, download) < 0:
        return None
    return upload / elapsed, download / elapsed
