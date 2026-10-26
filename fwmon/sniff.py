"""Capture passive des noms de domaine : DNS (port 53) et SNI TLS (443).

Utilise une socket AF_PACKET brute avec un filtre BPF attache dans le noyau,
afin de ne remonter que le trafic utile (pas de copie de tout le reseau).
"""

from __future__ import annotations

import ctypes
import socket
import struct
import threading

ETH_P_IP = 0x0800
ETH_P_IPV6 = 0x86DD
SO_ATTACH_FILTER = 26

BPF_LD = 0x00
BPF_JMP = 0x05
BPF_RET = 0x06
BPF_H = 0x08
BPF_B = 0x10
BPF_ABS = 0x20
BPF_JEQ = 0x10
BPF_K = 0x00

TLS_PORTS = (443, 8443, 853, 5228, 8883)
DNS_PORTS = (53, 853, 5353)


class _Asm:
    def __init__(self) -> None:
        self.items: list[list] = []
        self.labels: dict[str, int] = {}

    def label(self, name: str) -> None:
        self.labels[name] = len(self.items)

    def add(self, code: int, jt=None, jf=None, k: int = 0) -> None:
        self.items.append([code, jt, jf, k])

    def build(self) -> list[tuple[int, int, int, int]]:
        program = []
        for index, (code, jt, jf, k) in enumerate(self.items):
            def resolve(target):
                if target is None:
                    return 0
                if isinstance(target, int):
                    return target
                return self.labels[target] - (index + 1)

            program.append((code, resolve(jt), resolve(jf), k))
        return program


def _ports_block(asm: "_Asm", proto_offset: int, dport_offset: int, sport_offset: int) -> None:
    prefix = f"p{proto_offset}"
    asm.add(BPF_LD | BPF_B | BPF_ABS, k=proto_offset)
    asm.add(BPF_JMP | BPF_JEQ | BPF_K, jt=f"{prefix}tcp", jf=None, k=6)
    asm.add(BPF_JMP | BPF_JEQ | BPF_K, jt=f"{prefix}udp", jf=None, k=17)

    asm.label(f"{prefix}tcp")
    for offset in (dport_offset, sport_offset):
        asm.add(BPF_LD | BPF_H | BPF_ABS, k=offset)
        for port in TLS_PORTS:
            asm.add(BPF_JMP | BPF_JEQ | BPF_K, jt="pass", jf=None, k=port)

    asm.label(f"{prefix}udp")
    for offset in (dport_offset, sport_offset):
        asm.add(BPF_LD | BPF_H | BPF_ABS, k=offset)
        for port in DNS_PORTS:
            asm.add(BPF_JMP | BPF_JEQ | BPF_K, jt="pass", jf=None, k=port)
    asm.add(BPF_RET | BPF_K, k=0)


def _program() -> list:
    asm = _Asm()
    asm.add(BPF_LD | BPF_H | BPF_ABS, k=12)             # ethertype
    asm.add(BPF_JMP | BPF_JEQ | BPF_K, jt="v4", jf=None, k=ETH_P_IP)
    asm.add(BPF_JMP | BPF_JEQ | BPF_K, jt="v6", jf=None, k=0x86DD)
    asm.add(BPF_RET | BPF_K, k=0)                        # ni IPv4 ni IPv6

    asm.label("v4")
    _ports_block(asm, 23, 36, 34)

    asm.label("v6")
    _ports_block(asm, 20, 44, 46)

    asm.label("pass")
    asm.add(BPF_RET | BPF_K, k=0xFFFFFFFF)
    return asm.build()


class _SockFilter(ctypes.Structure):
    _fields_ = [
        ("code", ctypes.c_ushort),
        ("jt", ctypes.c_ubyte),
        ("jf", ctypes.c_ubyte),
        ("k", ctypes.c_uint32),
    ]


class _SockFprog(ctypes.Structure):
    _fields_ = [
        ("len", ctypes.c_ushort),
        ("filter", ctypes.POINTER(_SockFilter)),
    ]


def _attach_filter(sock: socket.socket, program: list) -> None:
    array = (_SockFilter * len(program))(*[_SockFilter(*ins) for ins in program])
    fprog = _SockFprog(len(program), array)
    sock.setsockopt(socket.SOL_SOCKET, SO_ATTACH_FILTER, bytes(fprog))


def _read_name(message: bytes, offset: int) -> tuple[str, int]:
    labels: list[str] = []
    hops = 0
    while offset < len(message) and hops < 16:
        length = message[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(message):
                break
            pointer = ((length & 0x3F) << 8) | message[offset + 1]
            nested, _ = _read_name(message, pointer)
            if nested:
                labels.append(nested)
            offset += 2
            break
        offset += 1
        labels.append(message[offset : offset + length].decode("ascii", "ignore"))
        offset += length
        hops += 1
    return ".".join(part for part in labels if part), offset


def parse_dns(message: bytes) -> list[tuple[str, str]]:
    """Retourne les paires (ip, nom) des reponses A/AAAA."""
    if len(message) < 12:
        return []
    try:
        qdcount, ancount = struct.unpack_from("!HH", message, 4)
    except struct.error:
        return []

    offset = 12
    for _ in range(qdcount):
        _, offset = _read_name(message, offset)
        offset += 4

    results: list[tuple[str, str]] = []
    for _ in range(ancount):
        if offset >= len(message):
            break
        name, offset = _read_name(message, offset)
        if offset + 10 > len(message):
            break
        rtype, _rclass, _ttl, rdlen = struct.unpack_from("!HHIH", message, offset)
        offset += 10
        rdata = message[offset : offset + rdlen]
        offset += rdlen
        if rtype == 1 and rdlen == 4:
            results.append((socket.inet_ntop(socket.AF_INET, rdata), name))
        elif rtype == 28 and rdlen == 16:
            try:
                results.append((socket.inet_ntop(socket.AF_INET6, rdata), name))
            except ValueError:
                pass
    return results


def parse_client_hello(payload: bytes) -> str | None:
    """Extrait le SNI d'un ClientHello TLS, ou None."""
    if len(payload) < 6 or payload[0] != 0x16 or payload[1] != 0x03:
        return None
    record_len = int.from_bytes(payload[3:5], "big")
    body = payload[5 : 5 + record_len]
    if len(body) < 4 or body[0] != 0x01:
        return None

    offset = 4  # type(1) + longueur(3)
    if len(body) < offset + 2 + 32:
        return None
    offset += 2 + 32  # version + random

    if offset >= len(body):
        return None
    offset += 1 + body[offset]  # session_id

    if offset + 2 > len(body):
        return None
    cs_len = int.from_bytes(body[offset : offset + 2], "big")
    offset += 2 + cs_len

    if offset >= len(body):
        return None
    offset += 1 + body[offset]  # compression

    if offset + 2 > len(body):
        return None
    ext_len = int.from_bytes(body[offset : offset + 2], "big")
    offset += 2
    end = min(len(body), offset + ext_len)

    while offset + 4 <= end:
        ext_type = int.from_bytes(body[offset : offset + 2], "big")
        ext_size = int.from_bytes(body[offset + 2 : offset + 4], "big")
        offset += 4
        if offset + ext_size > end:
            break
        if ext_type == 0 and ext_size >= 5:
            name_len = int.from_bytes(body[offset + 3 : offset + 5], "big")
            name = body[offset + 5 : offset + 5 + name_len].decode("ascii", "ignore")
            if name:
                return name
        offset += ext_size
    return None


class DomainSniffer:
    """Thread de capture DNS + SNI. Appelle `on_domain(ip, name, source, port)`."""

    def __init__(self, on_domain) -> None:
        self.on_domain = on_domain
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []
        self._seen_sni: set[tuple[str, int]] = set()
        self.error: str | None = None

    def start(self) -> None:
        thread = threading.Thread(target=self._loop, daemon=True, name="sniff")
        thread.start()
        self._threads.append(thread)

    def stop(self) -> None:
        self._stop.set()

    def _loop(self) -> None:
        try:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
        except (PermissionError, OSError) as exc:
            self.error = str(exc)
            return
        sock.settimeout(0.5)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 16 * 1024 * 1024)
        except OSError:
            pass
        try:
            try:
                _attach_filter(sock, _program())
            except OSError:
                pass

            while not self._stop.is_set():
                try:
                    frame = sock.recv(262144)
                except socket.timeout:
                    continue
                except OSError:
                    break
                try:
                    self._handle(frame)
                except (IndexError, struct.error, ValueError):
                    continue
        finally:
            sock.close()

    def _handle(self, frame: bytes) -> None:
        if len(frame) < 34:
            return
        ethertype = struct.unpack_from("!H", frame, 12)[0]
        if ethertype == ETH_P_IP:
            ihl = (frame[14] & 0x0F) * 4
            if ihl < 20:
                return
            proto = frame[23]
            src = socket.inet_ntop(socket.AF_INET, frame[26:30])
            dst = socket.inet_ntop(socket.AF_INET, frame[30:34])
            l4 = 14 + ihl
        elif ethertype == ETH_P_IPV6:
            if len(frame) < 54:
                return
            proto = frame[20]
            if proto not in (6, 17):
                return  # en-tetes d'extension non geres
            src = socket.inet_ntop(socket.AF_INET6, frame[22:38])
            dst = socket.inet_ntop(socket.AF_INET6, frame[38:54])
            l4 = 54
        else:
            return

        if proto == 17:
            if len(frame) < l4 + 8:
                return
            sport, dport = struct.unpack_from("!HH", frame, l4)
            if dport == 53 or sport == 53:
                for ip, name in parse_dns(frame[l4 + 8 :]):
                    self.on_domain(ip, name, "dns", 0)
            return

        if proto == 6:
            if len(frame) < l4 + 20:
                return
            dport = struct.unpack_from("!H", frame, l4 + 2)[0]
            if dport not in TLS_PORTS:
                return
            offset = (frame[l4 + 12] >> 4) * 4
            payload = frame[l4 + offset :]
            if len(payload) < 6:
                return
            if (dst, dport) in self._seen_sni:
                return
            name = parse_client_hello(payload)
            if name:
                if len(self._seen_sni) > 50000:
                    self._seen_sni.clear()
                self._seen_sni.add((dst, dport))
                self.on_domain(dst, name, "sni", dport)
