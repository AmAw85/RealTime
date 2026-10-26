"""Lecture des sockets du noyau via `ss -tunapie`."""

from __future__ import annotations

import pwd
import re
import subprocess
from dataclasses import dataclass

_USERS_RE = re.compile(r'users:\(\("([^"]+)",pid=(\d+)')
_BYTES_SENT_RE = re.compile(r"bytes_sent:(\d+)")
_BYTES_RECV_RE = re.compile(r"bytes_received:(\d+)")
_RTT_RE = re.compile(r"\brtt:([0-9.]+)/([0-9.]+)")
_UID_RE = re.compile(r"\buid:(\d+)")

LISTEN_STATES = {"LISTEN", "UNCONN"}

_uid_names: dict[int, str] = {}


def uid_name(uid: int) -> str:
    if uid not in _uid_names:
        try:
            _uid_names[uid] = pwd.getpwuid(uid).pw_name
        except KeyError:
            _uid_names[uid] = f"uid{uid}"
    return _uid_names[uid]


@dataclass(slots=True)
class Session:
    proto: str = ""
    local_ip: str = ""
    local_port: int = 0
    remote_ip: str = ""
    remote_port: int = 0
    state: str = ""
    pid: int = 0
    process: str = "-"
    uid: int = -1
    iface: str = ""
    tx: int = 0
    rx: int = 0
    rtt: float = 0.0

    def key(self) -> tuple:
        return (
            self.proto,
            self.local_ip,
            self.local_port,
            self.remote_ip,
            self.remote_port,
            self.pid,
        )

    def to_list(self) -> list:
        return [
            self.proto,
            self.local_ip,
            self.local_port,
            self.remote_ip,
            self.remote_port,
            self.state,
            self.pid,
            self.process,
            self.iface,
            self.tx,
            self.rx,
            self.rtt,
            self.uid,
        ]

    @classmethod
    def from_list(cls, data: list) -> "Session":
        return cls(
            proto=data[0],
            local_ip=data[1],
            local_port=data[2],
            remote_ip=data[3],
            remote_port=data[4],
            state=data[5],
            pid=data[6],
            process=data[7],
            iface=data[8],
            tx=data[9],
            rx=data[10],
            rtt=data[11],
            uid=data[12] if len(data) > 12 else -1,
        )


def split_addr(text: str) -> tuple[str, int, str]:
    """`10.0.0.1%eth0:443` -> ("10.0.0.1", 443, "eth0")"""
    if "]" in text:
        hostpart, _, port = text.rpartition("]:")
        hostpart += "]"
    elif ":" in text:
        hostpart, _, port = text.rpartition(":")
    else:
        hostpart, port = text, "0"
    iface = ""
    if "%" in hostpart:
        hostpart, iface = hostpart.split("%", 1)
    host = hostpart.strip("[]")
    try:
        number = int(port)
    except ValueError:
        number = 0
    return host, number, iface


def _parse_info(line: str, session: Session) -> None:
    m = _BYTES_SENT_RE.search(line)
    if m:
        session.tx = int(m.group(1))
    m = _BYTES_RECV_RE.search(line)
    if m:
        session.rx = int(m.group(1))
    m = _RTT_RE.search(line)
    if m:
        session.rtt = float(m.group(1))
    m = _UID_RE.search(line)
    if m:
        session.uid = int(m.group(1))


def parse_ss(timeout: float = 5.0) -> tuple[list[Session], list[Session]]:
    """Retourne (sessions actives, sockets en ecoute)."""
    try:
        out = subprocess.run(
            ["ss", "-tunapie"],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return [], []

    sessions: list[Session] = []
    listeners: list[Session] = []
    current: Session | None = None

    for line in out.splitlines():
        if not line.strip():
            continue
        if line[0] in " \t":
            if current is not None:
                _parse_info(line, current)
            continue

        parts = line.split()
        if len(parts) < 6 or parts[0] not in ("tcp", "udp"):
            current = None
            continue

        session = Session()
        session.proto = parts[0]
        session.state = parts[1]
        local_ip, local_port, iface = split_addr(parts[4])
        remote_ip, remote_port, _ = split_addr(parts[5])
        session.local_ip = local_ip
        session.local_port = local_port
        session.remote_ip = remote_ip
        session.remote_port = remote_port
        session.iface = iface

        tail = " ".join(parts[6:])
        m = _UID_RE.search(tail)
        if m:
            session.uid = int(m.group(1))
        m = _USERS_RE.search(tail)
        if m:
            session.process = m.group(1)
            session.pid = int(m.group(2))
        elif session.uid > 0:
            session.process = uid_name(session.uid)
        else:
            session.process = "(noyau)"

        current = session
        if session.state in ("TIME-WAIT", "CLOSE", "CLOSING"):
            continue
        if remote_port > 0:
            sessions.append(session)
        elif local_port > 0 and session.state in LISTEN_STATES:
            listeners.append(session)

    return sessions, listeners
