"""Collecteur privilegie : emet un flux NDJSON sur stdout.

Lance par l'interface via `sudox`. Ne fait aucune modification du systeme :
uniquement de la lecture (ss, /proc, ip) et de la capture passive.
"""

from __future__ import annotations

import ipaddress
import json
import os
import queue
import signal
import subprocess
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fwmon import __version__                       # noqa: E402
from fwmon.sniff import DomainSniffer               # noqa: E402
from fwmon.ssparse import parse_ss                  # noqa: E402

_emit_lock = threading.Lock()
_domain_cache: dict[str, tuple[str, float]] = {}
_sni_cache: dict[tuple[str, int], tuple[str, float]] = {}
_ptr_tried: dict[str, float] = {}
_ptr_queue: "queue.Queue[str]" = queue.Queue(maxsize=2000)
_proc_cache: dict[int, dict] = {}
_proc_seen: dict[int, float] = {}
_stop = threading.Event()


def emit(payload: dict) -> None:
    line = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
    with _emit_lock:
        try:
            sys.stdout.write(line + "\n")
            sys.stdout.flush()
        except (BrokenPipeError, ValueError):
            _stop.set()
            try:
                sys.stdout = open(os.devnull, "w")
            except OSError:
                pass


def iface_map() -> dict[str, str]:
    mapping: dict[str, str] = {}
    for family in ("-4", "-6"):
        try:
            out = subprocess.run(
                ["ip", "-o", family, "addr", "show"],
                capture_output=True, text=True, timeout=3, check=False,
            ).stdout
        except (OSError, subprocess.SubprocessError):
            continue
        for line in out.splitlines():
            parts = line.split()
            if len(parts) < 4:
                continue
            name = parts[1].rstrip(":")
            mapping[parts[3].split("/")[0]] = name
    return mapping


def is_private(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True
    if addr.is_loopback:
        return True
    return addr.is_private or addr.is_link_local or addr.is_multicast or addr.is_unspecified


def _ptr_worker() -> None:
    while not _stop.is_set():
        try:
            ip = _ptr_queue.get(timeout=0.5)
        except queue.Empty:
            continue
        try:
            name = socket_gethostbyaddr(ip)
        except OSError:
            name = None
        _ptr_tried[ip] = time.time()
        if name:
            _domain_cache[ip] = (name, time.time())
            emit({"t": "d", "ip": ip, "n": name, "s": "ptr", "p": 0})


def socket_gethostbyaddr(ip: str):
    import socket

    old = socket.getdefaulttimeout()
    socket.setdefaulttimeout(1.5)
    try:
        return socket.gethostbyaddr(ip)[0]
    finally:
        socket.setdefaulttimeout(old)


def _on_domain(ip: str, name: str, source: str, port: int) -> None:
    now = time.time()
    name = name.rstrip(".")
    if not name:
        return
    if source == "sni":
        _sni_cache[(ip, port)] = (name, now)
    _domain_cache[ip] = (name, now)
    emit({"t": "d", "ip": ip, "n": name, "s": source, "p": port})


def _cmdline(pid: int) -> str:
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as handle:
            raw = handle.read(4096)
    except OSError:
        return ""
    text = raw.replace(b"\x00", b" ").decode("utf-8", "replace").strip()
    if len(text) > 300:
        text = text[:297] + "..."
    return text


def _start_time(pid: int) -> int:
    """Champ 22 de /proc/<pid>/stat : permet de detecter la reutilisation d'un PID."""
    try:
        with open(f"/proc/{pid}/stat", "rb") as handle:
            raw = handle.read(4096)
        rest = raw.rsplit(b")", 1)[1].split()
        return int(rest[19])
    except (OSError, IndexError, ValueError):
        return -1


def _exe_path(pid: int) -> str:
    try:
        path = os.readlink(f"/proc/{pid}/exe")
    except OSError:
        return ""
    if path.endswith(" (deleted)"):
        path = path[: -len(" (deleted)")]
    return path


def _proc_info(pid: int) -> tuple[dict, bool]:
    """Infos du processus, re-emises si le PID a ete reutilise entre-temps."""
    start = _start_time(pid)
    _proc_seen[pid] = time.time()
    cached = _proc_cache.get(pid)
    if cached is not None and cached.get("start") == start:
        return cached, False
    info = {
        "t": "proc",
        "pid": pid,
        "cmd": _cmdline(pid),
        "exe": _exe_path(pid),
        "start": start,
    }
    _proc_cache[pid] = info
    return info, True


def main() -> int:
    signal.signal(signal.SIGINT, lambda *_: _stop.set())
    signal.signal(signal.SIGTERM, lambda *_: _stop.set())

    emit({
        "t": "hello",
        "v": __version__,
        "uid": os.getuid(),
        "pid": os.getpid(),
        "ss": True,
    })
    if os.getuid() != 0:
        emit({
            "t": "warn",
            "m": "collecte sans privileges : processus et chemins incomplets"
                 " (sudo -v avant lancement, ou configurer sudox)",
        })

    sniffer = DomainSniffer(_on_domain)
    try:
        sniffer.start()
    except Exception as exc:  # noqa: BLE001
        emit({"t": "err", "m": f"capture: {exc}"})

    for index in range(4):
        threading.Thread(target=_ptr_worker, daemon=True, name=f"ptr{index}").start()

    mapping = iface_map()
    last_map = time.time()
    known_ips: set[str] = set()

    while not _stop.is_set():
        started = time.monotonic()

        sessions, listeners = parse_ss()
        now = time.time()

        if now - last_map > 30:
            mapping = iface_map()
            last_map = now

        payload_sessions = []
        checked: set[int] = set()
        for session in sessions:
            if session.iface or session.local_ip in mapping:
                session.iface = session.iface or mapping.get(session.local_ip, "")
            payload_sessions.append(session.to_list())

            if session.pid and session.pid not in checked:
                checked.add(session.pid)
                info, changed = _proc_info(session.pid)
                if changed:
                    emit(info)

            remote = session.remote_ip
            if (
                remote
                and remote not in known_ips
                and not is_private(remote)
                and remote not in _domain_cache
                and now - _ptr_tried.get(remote, 0) > 1800
            ):
                known_ips.add(remote)
                try:
                    _ptr_queue.put_nowait(remote)
                except queue.Full:
                    known_ips.discard(remote)

        if len(_proc_seen) > 512:
            limit = now - 300
            for pid in [p for p, seen in _proc_seen.items() if seen < limit and p not in checked]:
                _proc_seen.pop(pid, None)
                _proc_cache.pop(pid, None)

        emit({
            "t": "snap",
            "ts": now,
            "s": payload_sessions,
            "l": [[x.proto, x.local_ip, x.local_port, x.pid, x.process] for x in listeners],
            "loc": sorted(mapping),
            "err": sniffer.error,
        })

        elapsed = time.monotonic() - started
        _stop.wait(max(0.05, 1.0 - elapsed))

    emit({"t": "bye"})
    return 0


if __name__ == "__main__":
    sys.exit(main())
