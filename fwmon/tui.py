"""Interface terminal (curses) de fwmon."""

from __future__ import annotations

import curses
import ipaddress
import json
import locale
import os
import pwd
import queue
import shutil
import signal
import subprocess
import sys
import threading
import time
from datetime import datetime

from fwmon import risk
from fwmon.ports import SERVICES
from fwmon.ssparse import Session

STATE_LABELS = {
    "ESTAB": "ÉTABLIE", "LISTEN": "ÉCOUTE", "UNCONN": "NON CONN.",
    "SYN-SENT": "SYN ENVOYÉ", "SYN-RECV": "SYN REÇU", "FIN-WAIT-1": "FERMETURE",
    "FIN-WAIT-2": "FERMETURE", "CLOSE-WAIT": "ATT. FERM.", "LAST-ACK": "DERNIER ACK",
    "TIME-WAIT": "ATT. TEMPS", "CLOSE": "FERMÉ",
}

TAB_APPS, TAB_CONNS, TAB_DOMAINS, TAB_IN, TAB_ALERTS = 0, 1, 2, 3, 4
TAB_NAMES = ["Applications", "Connexions", "Domaines", "Entrant", "Alertes"]

SORTS = {
    TAB_APPS: ["trafic", "nom", "connexions", "reception", "risque"],
    TAB_CONNS: ["trafic", "nom", "destination", "risque"],
    TAB_DOMAINS: ["trafic", "nom", "connexions"],
    TAB_IN: ["trafic", "nom"],
    TAB_ALERTS: ["risque", "nom"],
}

LEVEL_COLORS = {"élevé": 4, "moyen": 3, "faible": 1}

ALERT_LABELS = {
    "processus_inconnu": "processus inconnu",
    "exe_indisponible": "exe indisponible",
    "exe_hors_systeme": "exe hors système",
    "exe_suspect": "exe suspect",
    "service_sensible": "service sensible",
    "port_inhabituel": "port inhabituel",
    "entrant_wan": "entrant WAN",
    "connexions_nombreuses": "nb connexions",
    "tentatives_repetees": "tentatives répétées",
}

STATE_FILTERS = ["", "actives", "inactives"]
PROTO_FILTERS = ["", "tcp", "udp"]
RISK_FILTERS = ["", "moyen", "élevé"]
STATE_FILTER_LABELS = {"": "toutes", "actives": "établies", "inactives": "autres"}
PROTO_FILTER_LABELS = {"": "tous", "tcp": "tcp", "udp": "udp"}
RISK_FILTER_LABELS = {"": "tous", "moyen": "moyen+", "élevé": "élevé"}


def is_loopback(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_loopback
    except ValueError:
        return False


def is_local_scope(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast


def state_label(state: str) -> str:
    return STATE_LABELS.get(state, state)


def service_name(port: int) -> str:
    return SERVICES.get(port, str(port) if port else "-")


def fbytes(value: int) -> str:
    if not value:
        return "-"
    units = ("o", "Ko", "Mo", "Go", "To")
    number = float(value)
    index = 0
    while number >= 1024 and index < len(units) - 1:
        number /= 1024
        index += 1
    if index == 0:
        return f"{int(number)} o"
    return f"{number:.1f} {units[index]}"


def fage(seconds: float) -> str:
    if seconds < 0:
        return "-"
    if seconds < 60:
        return f"{int(seconds)} s"
    if seconds < 3600:
        return f"{int(seconds / 60)} min"
    return f"{seconds / 3600:.1f} h"


def cut(text: str, width: int) -> str:
    if width <= 0:
        return ""
    if len(text) <= width:
        return text
    if width == 1:
        return text[:1]
    return text[: width - 1] + "…"


class Model:
    def __init__(self) -> None:
        self.sessions: list[Session] = []
        self.prev: dict[tuple, Session] = {}
        self.listeners: dict[str, set[int]] = {"tcp": set(), "udp": set()}
        self.locals: set[str] = set()
        self.domains: dict[str, str] = {}
        self.sni: dict[tuple[str, int], str] = {}
        self.procs: dict[int, str] = {}
        self.exe: dict[int, str] = {}
        self.exe_known: set[int] = set()
        self.proc_start: dict[int, int] = {}
        self.pid_seen: dict[int, float] = {}
        self.warn = ""
        self.activity: dict[tuple, float] = {}
        self.recent: dict[tuple, list[float]] = {}
        self.alerts: dict[tuple, list] = {}
        self.app_alerts: dict[str, list] = {}
        self._owners: dict[int, str] = {}
        self.closed_apps: dict[str, list[int]] = {}
        self.closed_domains: dict[str, list[float]] = {}
        self.app_sites: dict[str, dict[str, float]] = {}
        self.first_seen: dict[tuple, float] = {}
        self.last_active: dict[str, float] = {}
        self.hello: dict = {}
        self.error: str | None = None
        self.paused = False
        self.snapshots = 0

    # -- ingestion -------------------------------------------------
    def apply(self, msg: dict) -> None:
        kind = msg.get("t")
        if kind == "hello":
            self.hello = msg
            return
        if kind == "err":
            self.error = msg.get("m", "erreur inconnue")
            return
        if kind == "proc":
            pid = int(msg["pid"])
            self.procs[pid] = msg.get("cmd", "")
            self.exe[pid] = msg.get("exe", "")
            self.exe_known.add(pid)
            self.proc_start[pid] = int(msg.get("start", -1))
            return
        if kind == "warn":
            self.warn = str(msg.get("m", ""))
            return
        if kind == "d":
            ip = msg.get("ip", "")
            name = msg.get("n", "")
            if not ip or not name:
                return
            port = int(msg.get("p", 0))
            self.domains[ip] = name
            if port:
                self.sni[(ip, port)] = name
            return
        if kind != "snap" or self.paused:
            return

        now = time.time()
        fresh: dict[tuple, Session] = {}
        for data in msg.get("s", []):
            session = Session.from_list(data)
            fresh[session.key()] = session
            if session.key() not in self.first_seen:
                self.first_seen[session.key()] = now

        for key, session in fresh.items():
            old = self.prev.get(key)
            if old is None or (old.tx, old.rx) != (session.tx, session.rx):
                self.activity[key] = now

        for key, session in fresh.items():
            if key in self.prev:
                continue
            dest = (session.process, session.remote_ip, session.remote_port)
            self.recent.setdefault(dest, []).append(now)

        for dest in list(self.recent):
            times = [stamp for stamp in self.recent[dest] if now - stamp <= risk.REPEAT_WINDOW]
            if times:
                self.recent[dest] = times
            else:
                del self.recent[dest]

        for key, session in self.prev.items():
            if key in fresh:
                continue
            bucket = self.closed_apps.setdefault(session.process, [0, 0])
            bucket[0] += session.tx
            bucket[1] += session.rx
            domain = self.domain_for(session)
            if domain and domain != session.remote_ip:
                self.app_sites.setdefault(session.process, {})[domain] = now
                d = self.closed_domains.setdefault(domain, [0, 0, now])
                d[0] += session.tx
                d[1] += session.rx
                d[2] = now

        live_keys = set(fresh)
        for key in list(self.first_seen):
            if key not in live_keys and key not in self.prev:
                del self.first_seen[key]

        self.prev = fresh
        self.sessions = list(fresh.values())
        self.locals = set(msg.get("loc", []))
        listeners: dict[str, set[int]] = {"tcp": set(), "udp": set()}
        for proto, _ip, port, _pid, _name in msg.get("l", []):
            listeners.setdefault(proto, set()).add(int(port))
        self.listeners = listeners
        self.snapshots += 1
        for session in self.sessions:
            self.last_active[session.process] = now
            if session.pid:
                self.pid_seen[session.pid] = now
        self.recompute_alerts()

    # -- helpers ---------------------------------------------------
    def domain_for(self, session: Session) -> str:
        name = self.sni.get((session.remote_ip, session.remote_port))
        if not name:
            name = self.domains.get(session.remote_ip)
        return name or session.remote_ip

    def direction(self, session: Session) -> str:
        if is_loopback(session.local_ip) or is_loopback(session.remote_ip):
            return "LOCAL"
        if session.local_port in self.listeners.get(session.proto, set()):
            return "IN"
        return "OUT"

    def service_for(self, session: Session) -> str:
        if self.direction(session) == "LOCAL":
            for port in (session.remote_port, session.local_port):
                if port in SERVICES:
                    return SERVICES[port]
            return "local"
        if self.direction(session) == "IN":
            return service_name(session.local_port)
        return service_name(session.remote_port)

    def scope(self, session: Session) -> str:
        if is_loopback(session.remote_ip):
            return "LOCAL"
        return "LAN" if is_local_scope(session.remote_ip) else "WAN"

    def age(self, session: Session) -> float:
        return time.time() - self.first_seen.get(session.key(), time.time())

    def owner(self, uid: int) -> str:
        if uid < 0:
            return "-"
        if uid not in self._owners:
            try:
                self._owners[uid] = pwd.getpwuid(uid).pw_name
            except KeyError:
                self._owners[uid] = f"uid{uid}"
        return self._owners[uid]

    def exe_for(self, session: Session) -> str:
        if session.pid <= 0:
            return ""
        return self.exe.get(session.pid, "")

    def idle(self, session: Session) -> float:
        stamp = self.activity.get(session.key())
        return time.time() - stamp if stamp else 0.0

    def level_of(self, session: Session) -> str:
        return risk.worst(self.alerts.get(session.key(), []))

    def alerts_of(self, session: Session) -> list:
        return self.alerts.get(session.key(), [])

    def app_level(self, name: str) -> str:
        levels = [a.level for a in self.app_alerts.get(name, [])]
        levels += [self.level_of(s) for s in self.sessions if s.process == name]
        levels = [level for level in levels if level]
        if not levels:
            return ""
        return max(levels, key=risk.level_rank)

    def recompute_alerts(self) -> None:
        self.alerts = {}
        self.app_alerts = {}
        counts: dict[str, int] = {}
        for session in self.sessions:
            counts[session.process] = counts.get(session.process, 0) + 1

        for session in self.sessions:
            repeats = len(self.recent.get(
                (session.process, session.remote_ip, session.remote_port), ()))
            ctx = risk.Context(
                process=session.process,
                pid=session.pid,
                owner=self.owner(session.uid),
                exe=self.exe_for(session),
                exe_known=session.pid in self.exe_known,
                direction=self.direction(session),
                scope=self.scope(session),
                proto=session.proto,
                local_port=session.local_port,
                remote_port=session.remote_port,
                state=session.state,
                domain=self.domain_for(session),
                conns_for_app=0,
                repeats=repeats,
            )
            found = risk.evaluate(ctx)
            if found:
                self.alerts[session.key()] = found

        for name, count in counts.items():
            if count < risk.MANY_CONNS_MEDIUM:
                continue
            probe = risk.Context(process=name, pid=1, conns_for_app=count, state="")
            found = [a for a in risk.evaluate(probe) if a.code == "connexions_nombreuses"]
            if found:
                self.app_alerts[name] = found

        cutoff = time.time() - 900
        for pid in [p for p, seen in self.pid_seen.items() if seen < cutoff]:
            self.pid_seen.pop(pid, None)
            self.procs.pop(pid, None)
            self.exe.pop(pid, None)
            self.exe_known.discard(pid)
            self.proc_start.pop(pid, None)

    def session_dir(self, session: Session) -> str:
        return self.direction(session)

    # -- aggregation ------------------------------------------------
    def aggregate_apps(self) -> list[dict]:
        apps: dict[str, dict] = {}

        def bucket(name: str) -> dict:
            if name not in apps:
                apps[name] = {
                    "name": name, "pids": set(), "conns": 0, "tx": 0, "rx": 0,
                    "services": {}, "sites": {}, "live": 0, "ins": 0,
                }
            return apps[name]

        for session in self.sessions:
            app = bucket(session.process)
            app["pids"].add(session.pid)
            app["conns"] += 1
            app["live"] += 1
            app["tx"] += session.tx
            app["rx"] += session.rx
            if self.direction(session) == "IN":
                app["ins"] += 1
            service = self.service_for(session)
            app["services"][service] = app["services"].get(service, 0) + 1
            domain = self.domain_for(session)
            app["sites"][domain] = app["sites"].get(domain, 0) + session.tx + session.rx

        for name, (tx, rx) in self.closed_apps.items():
            app = bucket(name)
            app["tx"] += tx
            app["rx"] += rx

        for name, sites in self.app_sites.items():
            app = bucket(name)
            for domain in sites:
                app["sites"].setdefault(domain, 0)

        for app in apps.values():
            if app["conns"]:
                top_service = max(app["services"], key=app["services"].get)
                ranked = sorted(app["sites"], key=app["sites"].get, reverse=True)
                top_sites = [s for s in ranked if s and s != "-" and not is_loopback(s)][:2]
                if not top_sites:
                    top_sites = [s for s in ranked if s and s != "-"][:2]
                parts = [top_service] if top_service else []
                if top_sites:
                    parts.append(", ".join(top_sites))
                app["activity"] = " · ".join(parts) or "-"
                app["active"] = True
            else:
                top_sites = sorted(app["sites"], key=app["sites"].get, reverse=True)
                app["activity"] = "inactif · " + top_sites[0] if top_sites else "inactif"
                app["active"] = False

        now = time.time()
        return [
            app for app in apps.values()
            if app["conns"] or now - self.last_active.get(app["name"], 0) < 900
        ]

    def aggregate_domains(self) -> list[dict]:
        domains: dict[str, dict] = {}

        def bucket(name: str) -> dict:
            if name not in domains:
                domains[name] = {"name": name, "apps": set(), "conns": 0, "tx": 0, "rx": 0, "last": 0.0}
            return domains[name]

        for session in self.sessions:
            name = self.domain_for(session)
            item = bucket(name)
            item["apps"].add(session.process)
            item["conns"] += 1
            item["tx"] += session.tx
            item["rx"] += session.rx
            item["last"] = time.time()

        for name, (tx, rx, last) in self.closed_domains.items():
            if name in domains:
                continue
            item = bucket(name)
            item["tx"] += tx
            item["rx"] += rx
            item["last"] = last

        return list(domains.values())

    def inbound(self) -> list[Session]:
        return [s for s in self.sessions if self.direction(s) == "IN"]


class Collector:
    def __init__(self) -> None:
        self.proc: subprocess.Popen | None = None
        self.queue: queue.Queue = queue.Queue()
        self.stderr: list[str] = []
        self.privileged = False
        self.command = ""

    def start(self) -> None:
        base = os.path.dirname(os.path.abspath(__file__))
        script = os.path.join(base, "collector.py")
        command = [sys.executable, script]
        sudox = shutil.which("sudox") or os.path.expanduser("~/.local/bin/sudox")
        if sudox and os.access(sudox, os.X_OK):
            command = [sudox] + command
            self.privileged = True
        elif shutil.which("sudo"):
            # sudo sans mot de passe (session deja deverrouillee avec `sudo -v`) :
            # evite d'inviter au mot de passe au milieu de l'ecran curses.
            try:
                check = subprocess.run(
                    ["sudo", "-n", "true"], capture_output=True, timeout=3,
                )
            except (OSError, subprocess.SubprocessError):
                check = None
            if check is not None and check.returncode == 0:
                command = ["sudo", "-n"] + command
                self.privileged = True
        self.command = " ".join(command)
        self.proc = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            start_new_session=True,
        )
        threading.Thread(target=self._read_stdout, daemon=True).start()
        threading.Thread(target=self._read_stderr, daemon=True).start()

    def _read_stdout(self) -> None:
        assert self.proc and self.proc.stdout
        for line in self.proc.stdout:
            line = line.strip()
            if not line:
                continue
            try:
                self.queue.put(json.loads(line))
            except json.JSONDecodeError:
                continue

    def _read_stderr(self) -> None:
        assert self.proc and self.proc.stderr
        for line in self.proc.stderr:
            line = line.strip()
            if line:
                self.stderr.append(line)
                del self.stderr[:-5]

    def stop(self) -> None:
        if not self.proc or self.proc.poll() is not None:
            return
        try:
            os.killpg(os.getpgid(self.proc.pid), signal.SIGTERM)
        except OSError:
            try:
                self.proc.terminate()
            except OSError:
                pass
        try:
            self.proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(os.getpgid(self.proc.pid), signal.SIGKILL)
            except OSError:
                pass


class UI:
    def __init__(self, stdscr) -> None:
        self.stdscr = stdscr
        self.model = Model()
        self.collector = Collector()
        self.tab = TAB_APPS
        self.sel = 0
        self.offset = 0
        self.sort_index = {tab: 0 for tab in SORTS}
        self.filter = ""
        self.state_filter = ""
        self.proto_filter = ""
        self.risk_filter = ""
        self.detail = None
        self.detail_sel = 0
        self.detail_offset = 0
        self.running = True
        self.status = ""
        self.fatal: str | None = None

    # -- curses setup ----------------------------------------------
    def setup(self) -> None:
        curses.curs_set(0)
        self.stdscr.nodelay(True)
        self.stdscr.timeout(150)
        curses.use_default_colors()
        try:
            curses.init_pair(1, curses.COLOR_GREEN, -1)
            curses.init_pair(2, curses.COLOR_CYAN, -1)
            curses.init_pair(3, curses.COLOR_YELLOW, -1)
            curses.init_pair(4, curses.COLOR_RED, -1)
            curses.init_pair(5, curses.COLOR_MAGENTA, -1)
            curses.init_pair(6, curses.COLOR_BLUE, -1)
            self.has_color = True
        except curses.error:
            self.has_color = False

    def attr(self, pair: int, bold: bool = False) -> int:
        if not self.has_color:
            return curses.A_BOLD if bold else curses.A_NORMAL
        value = curses.color_pair(pair)
        return value | curses.A_BOLD if bold else value

    # -- helpers ---------------------------------------------------
    def _put(self, y: int, x: int, text: str, attr: int = 0, width: int | None = None) -> None:
        height, cols = self.stdscr.getmaxyx()
        if y < 0 or y >= height or x >= cols:
            return
        room = cols - x if width is None else min(width, cols - x)
        if room <= 0:
            return
        try:
            self.stdscr.addnstr(y, x, text, room, attr)
        except (curses.error, UnicodeEncodeError):
            try:
                self.stdscr.addnstr(y, x, text.encode("ascii", "replace").decode(), room, attr)
            except curses.error:
                pass

    def _bar(self, y: int, text: str, attr: int) -> None:
        _height, cols = self.stdscr.getmaxyx()
        self._put(y, 0, " " * max(1, cols - 1), attr)
        self._put(y, 1, text, attr, max(1, cols - 2))

    def _sort_key(self) -> str:
        return SORTS[self.tab][self.sort_index[self.tab]]

    # -- data views ------------------------------------------------
    def _filter_match(self, *values: str) -> bool:
        if not self.filter:
            return True
        needle = self.filter.lower()
        return any(needle in str(value or "").lower() for value in values)

    def _state_ok(self, session: Session) -> bool:
        if not self.state_filter:
            return True
        if self.state_filter == "actives":
            return session.state == "ESTAB"
        return session.state != "ESTAB"

    def _proto_ok(self, session: Session) -> bool:
        return not self.proto_filter or session.proto == self.proto_filter

    def _risk_ok(self, level: str) -> bool:
        if not self.risk_filter:
            return True
        return risk.level_rank(level) >= risk.level_rank(self.risk_filter)

    def _session_match(self, session: Session) -> bool:
        domain = self.model.domain_for(session)
        return (
            self._state_ok(session)
            and self._proto_ok(session)
            and self._risk_ok(self.model.level_of(session))
            and self._filter_match(
                session.process, domain, session.remote_ip, session.remote_port,
                session.local_ip, session.local_port, session.pid, session.proto,
                state_label(session.state), self.model.owner(session.uid),
                self.model.exe_for(session),
            )
        )

    def view_apps(self, cols: int = 0):
        rows = []
        for app in self.model.aggregate_apps():
            if not self._filter_match(
                app["name"], app["activity"], *[str(p) for p in app["pids"]]
            ):
                continue
            if self.risk_filter and not self._risk_ok(self.model.app_level(app["name"])):
                continue
            rows.append(app)
        key = self._sort_key()
        if key == "nom":
            rows.sort(key=lambda a: a["name"].lower())
        elif key == "connexions":
            rows.sort(key=lambda a: (a["conns"], a["tx"] + a["rx"]), reverse=True)
        elif key == "reception":
            rows.sort(key=lambda a: a["rx"], reverse=True)
        elif key == "risque":
            rows.sort(
                key=lambda a: (risk.level_rank(self.model.app_level(a["name"])), a["tx"] + a["rx"]),
                reverse=True,
            )
        else:
            rows.sort(key=lambda a: a["tx"] + a["rx"], reverse=True)

        headers = [
            ("APPLICATION", 18), ("PID", 7), ("CONN", 5), ("↑ ENVOYÉ", 10),
            ("↓ REÇU", 10), ("ALERTE", 7), ("ACTIVITÉ", -1),
        ]
        out = []
        for app in rows:
            pid = min(app["pids"]) if app["pids"] else 0
            dim = 0 if app["active"] else curses.A_DIM
            level = self.model.app_level(app["name"])
            risk_cell = (level, self.attr(LEVEL_COLORS[level], True) if level else curses.A_DIM)
            cells = [
                ((app["name"], dim),),
                ((str(pid) if pid else "-", dim),),
                ((str(app["conns"]), dim),),
                ((fbytes(app["tx"]), dim | self.attr(3)),),
                ((fbytes(app["rx"]), dim | self.attr(1)),),
                ((risk_cell[0] or "-", risk_cell[1]),),
                ((app["activity"], dim),),
            ]
            out.append((cells, ("app", app)))
        return headers, out

    def view_conns(self, cols: int = 0):
        sessions = list(self.model.sessions)
        rows = []
        for session in sessions:
            if not self._session_match(session):
                continue
            domain = self.model.domain_for(session)
            direction = self.model.direction(session)
            rows.append((session, domain, direction))
        key = self._sort_key()
        if key == "nom":
            rows.sort(key=lambda r: (r[0].process.lower(), r[1]))
        elif key == "destination":
            rows.sort(key=lambda r: (r[1], r[0].remote_port))
        elif key == "risque":
            rows.sort(
                key=lambda r: (risk.level_rank(self.model.level_of(r[0])), r[0].tx + r[0].rx),
                reverse=True,
            )
        else:
            rows.sort(key=lambda r: r[0].tx + r[0].rx, reverse=True)

        compact = cols < 120
        headers = [
            ("APPLICATION", 14 if compact else 15), ("UTILISATEUR", 11), ("DIR", 5),
            ("DOMAINE / HÔTE", -1), ("DESTINATION", 21),
            ("SERVICE", 8), ("ÉTAT", 9 if compact else 11), ("ACTIVITÉ", 8),
            ("↑", 6 if compact else 7), ("↓", 6 if compact else 7), ("RISQUE", 7),
        ]
        dropped = {1, 4, 7} if compact else set()
        headers = [h for index, h in enumerate(headers) if index not in dropped]

        now = time.time()
        out = []
        for session, domain, direction in rows:
            color = self.attr(2) if direction == "IN" else (
                curses.A_DIM if direction == "LOCAL" else self.attr(1)
            )
            idle = self.model.idle(session)
            inactive = session.state == "ESTAB" and idle > 60
            dim = curses.A_DIM if inactive else 0
            level = self.model.level_of(session)
            risk_attr = self.attr(LEVEL_COLORS[level], True) if level else curses.A_DIM
            dest = f"{session.remote_ip}:{session.remote_port}"
            cells = [
                ((cut(session.process, 14 if compact else 15), dim),),
                ((cut(self.model.owner(session.uid), 11), dim),),
                ((direction, color),),
                ((cut(domain, 60), dim),),
                ((dest, dim),),
                ((self.model.service_for(session), dim),),
                ((state_label(session.state), dim),),
                (("actif" if idle < 15 else fage(idle), dim),),
                ((fbytes(session.tx), dim),),
                ((fbytes(session.rx), dim),),
                ((level or "-", risk_attr),),
            ]
            cells = [c for index, c in enumerate(cells) if index not in dropped]
            out.append((cells, ("session", session)))
        return headers, out

    def view_domains(self, cols: int = 0):
        rows = []
        for item in self.model.aggregate_domains():
            if not self._filter_match(item["name"], *item["apps"]):
                continue
            rows.append(item)
        key = self._sort_key()
        if key == "nom":
            rows.sort(key=lambda d: d["name"].lower())
        elif key == "connexions":
            rows.sort(key=lambda d: d["conns"], reverse=True)
        else:
            rows.sort(key=lambda d: d["tx"] + d["rx"], reverse=True)

        headers = [("DOMAINE / HÔTE", -1), ("APPLICATIONS", 24), ("CONN", 5), ("↑", 9), ("↓", 9), ("VU", 8)]
        out = []
        for item in rows:
            apps = ", ".join(sorted(item["apps"])) if item["apps"] else "-"
            seen = fage(time.time() - item["last"]) if item["last"] else "-"
            cells = [
                ((item["name"],),),
                ((cut(apps, 24),),),
                ((str(item["conns"]),),),
                ((fbytes(item["tx"]), self.attr(3)),),
                ((fbytes(item["rx"]), self.attr(1)),),
                ((seen, curses.A_DIM),),
            ]
            out.append((cells, ("domain", item)))
        return headers, out

    def view_inbound(self, cols: int = 0):
        rows = []
        for session in self.model.inbound():
            if not self._session_match(session):
                continue
            rows.append((session, self.model.domain_for(session)))
        key = self._sort_key()
        if key == "nom":
            rows.sort(key=lambda r: r[0].process.lower())
        else:
            rows.sort(key=lambda r: r[0].tx + r[0].rx, reverse=True)

        compact = cols < 110
        headers = [
            ("APPLICATION", 16), ("SENS", 5), ("SOURCE DISTANTE", 22), ("DOMAINE", -1),
            ("SERVICE", 9), ("PORT LOCAL", 10), ("↑", 7), ("↓", 7),
        ]
        dropped = {3} if compact else set()
        headers = [h for index, h in enumerate(headers) if index not in dropped]
        out = []
        for session, domain in rows:
            color = self.attr(2)
            cells = [
                ((cut(session.process, 16),),),
                (("IN", color),),
                ((f"{session.remote_ip}:{session.remote_port}", color),),
                ((cut(domain, 50),),),
                ((service_name(session.local_port),),),
                ((str(session.local_port),),),
                ((fbytes(session.tx),),),
                ((fbytes(session.rx),),),
            ]
            cells = [c for index, c in enumerate(cells) if index not in dropped]
            out.append((cells, ("session", session)))
        return headers, out

    def view_alerts(self, cols: int = 0):
        groups: dict[tuple, dict] = {}
        for session in self.model.sessions:
            for alert in self.model.alerts_of(session):
                key = (alert.code, alert.level, session.process, alert.reason)
                item = groups.setdefault(key, {
                    "alert": alert, "process": session.process, "count": 0,
                    "session": session,
                })
                item["count"] += 1
                item["session"] = session
        for name, alerts in self.model.app_alerts.items():
            example = next((s for s in self.model.sessions if s.process == name), None)
            if example is None:
                continue
            for alert in alerts:
                key = (alert.code, alert.level, name, alert.reason)
                groups.setdefault(key, {
                    "alert": alert,
                    "process": name,
                    "count": sum(1 for s in self.model.sessions if s.process == name),
                    "session": example,
                })

        rows = []
        for item in groups.values():
            alert = item["alert"]
            if not self._risk_ok(alert.level):
                continue
            if not self._filter_match(
                item["process"], alert.reason, alert.advice,
                ALERT_LABELS.get(alert.code, alert.code),
            ):
                continue
            rows.append(item)
        key = self._sort_key()
        if key == "nom":
            rows.sort(key=lambda r: (r["process"].lower(), r["alert"].reason))
        else:
            rows.sort(
                key=lambda r: (risk.level_rank(r["alert"].level), r["count"]),
                reverse=True,
            )

        compact = cols < 110
        headers = [
            ("RISQUE", 7), ("APPLICATION", 14 if compact else 15), ("TYPE", 20),
            ("RAISON", -1), ("CONN", 5), ("CONSEIL", 44),
        ]
        dropped = {2, 5} if compact else set()
        headers = [h for index, h in enumerate(headers) if index not in dropped]
        out = []
        for item in rows:
            alert = item["alert"]
            attr = self.attr(LEVEL_COLORS[alert.level], True)
            cells = [
                ((alert.level, attr),),
                ((cut(item["process"], 14 if compact else 15),),),
                ((cut(ALERT_LABELS.get(alert.code, alert.code), 20),),),
                ((cut(alert.reason, 160),),),
                ((str(item["count"]),),),
                ((cut(alert.advice, 44), curses.A_DIM),),
            ]
            cells = [c for index, c in enumerate(cells) if index not in dropped]
            out.append((cells, ("session", item["session"])))
        return headers, out

    def alert_counts(self) -> dict[str, int]:
        counts = {"élevé": 0, "moyen": 0, "faible": 0}
        groups = list(self.model.alerts.values()) + list(self.model.app_alerts.values())
        for alerts in groups:
            for alert in alerts:
                counts[alert.level] = counts.get(alert.level, 0) + 1
        return counts

    def current_view(self, cols: int = 0):
        if not cols:
            cols = self.stdscr.getmaxyx()[1]
        if self.tab == TAB_APPS:
            return self.view_apps(cols)
        if self.tab == TAB_CONNS:
            return self.view_conns(cols)
        if self.tab == TAB_DOMAINS:
            return self.view_domains(cols)
        if self.tab == TAB_ALERTS:
            return self.view_alerts(cols)
        return self.view_inbound(cols)

    # -- drawing ---------------------------------------------------
    def draw(self) -> None:
        self.stdscr.erase()
        height, cols = self.stdscr.getmaxyx()
        if height < 8 or cols < 60:
            self._put(0, 0, "Fenêtre trop petite (min 60x8)", self.attr(4, True))
            self.stdscr.refresh()
            return

        if self.detail:
            self.draw_detail(height, cols)
        else:
            self.draw_main(height, cols)
        self.stdscr.refresh()

    def _header(self, height: int, cols: int, subtitle: str) -> None:
        clock = datetime.now().strftime("%H:%M:%S")
        uid = self.model.hello.get("uid", os.getuid())
        badge = "root" if uid == 0 else "utilisateur"
        paused = "  ⏸ PAUSE" if self.model.paused else ""
        text = f" fwmon · Surveillance réseau   {clock}   [{badge}]{paused}   {subtitle}"
        self._bar(0, text, self.attr(6, True))

    def draw_main(self, height: int, cols: int) -> None:
        headers, rows = self.current_view(cols)
        apps = self.model.aggregate_apps()
        total_tx = sum(a["tx"] for a in apps)
        total_rx = sum(a["rx"] for a in apps)
        counts = self.alert_counts()
        alert_total = sum(counts.values())
        subtitle = f"{len(apps)} applis · {len(self.model.sessions)} sessions"
        if cols >= 100:
            subtitle += f" · ↑{fbytes(total_tx)} ↓{fbytes(total_rx)}"
        if alert_total:
            subtitle += f" · ⚠ {alert_total} alerte{'s' if alert_total > 1 else ''}"
        self._header(height, cols, subtitle)

        x = 1
        for index, name in enumerate(TAB_NAMES):
            label = f" {index + 1}:{name} "
            if index == TAB_ALERTS and alert_total:
                label = f" {index + 1}:{name} ({alert_total}) "
            active = index == self.tab
            attr = self.attr(6, True) if active else curses.A_DIM
            if index == TAB_ALERTS and counts["élevé"]:
                attr = self.attr(4, True)
            self._put(1, x, label, attr)
            x += len(label) + 1
        summary = []
        if self.filter:
            summary.append(f"« {self.filter} »")
        if self.state_filter:
            summary.append("F:" + STATE_FILTER_LABELS[self.state_filter])
        if self.proto_filter:
            summary.append("T:" + PROTO_FILTER_LABELS[self.proto_filter])
        if self.risk_filter:
            summary.append("R:" + RISK_FILTER_LABELS[self.risk_filter])
        if summary:
            self._put(1, x + 1, " · ".join(summary), self.attr(3))
        if self.model.paused:
            self._put(1, cols - 8, " PAUSE ", self.attr(4, True))

        self.draw_table(2, height - 2, headers, rows, cols, offset=self.offset, highlight=self.sel)
        self.draw_footer(height, cols, len(rows))
        if not self.model.hello and not self.model.error:
            self._put(height - 2, 2, "Démarrage du collecteur (droits root)…", self.attr(3))
        elif self.model.warn and not self.model.error:
            self._put(height - 2, 2, "⚠ " + self.model.warn, self.attr(3))
        if self.tab == TAB_IN and not rows:
            count = sum(len(v) for v in self.model.listeners.values())
            self._put(
                4, 2,
                f"{count} ports en écoute sur cette machine — aucune connexion entrante pour l'instant",
                curses.A_DIM,
            )

    def draw_table(self, top: int, bottom: int, headers, rows, cols: int,
                   offset: int = 0, highlight: int = -1) -> int:
        widths = []
        gaps = len(headers) - 1
        fixed = sum(width for _text, width in headers if width > 0)
        flexible = cols - 1 - fixed - gaps
        for _text, width in headers:
            widths.append(max(4, flexible) if width < 0 else width)

        x = 1
        for (text, _width), width in zip(headers, widths):
            self._put(top, x, cut(text, width), self.attr(5, True), width)
            x += width + 1

        available = bottom - top - 1
        if available <= 0:
            return 0

        if highlight >= 0:
            highlight = max(0, min(highlight, max(0, len(rows) - 1)))
            if highlight < offset:
                offset = highlight
            if highlight >= offset + available:
                offset = highlight - available + 1
        offset = max(0, min(offset, max(0, len(rows) - available)))

        for index in range(offset, min(len(rows), offset + available)):
            y = top + 1 + (index - offset)
            cells, _obj = rows[index]
            selected = index == highlight
            x = 1
            if selected:
                self._put(y, 0, " " * max(1, cols - 1), curses.A_REVERSE)
            for cell, width in zip(cells, widths):
                if isinstance(cell[0], tuple):
                    inner = cell[0]
                    text = inner[0]
                    attr = inner[1] if len(inner) > 1 else 0
                else:
                    text, attr = cell
                base = curses.A_REVERSE if selected else attr
                self._put(y, x, cut(text, width), base, width)
                x += width + 1

        if not rows:
            message = "  Aucune session" if not self.filter else "  Aucun résultat pour ce filtre"
            self._put(top + 1, 2, message, curses.A_DIM)
        return offset

    def draw_footer(self, height: int, cols: int, count: int) -> None:
        if self.model.error:
            self._bar(height - 1, f" ERREUR : {self.model.error} ", self.attr(4, True))
            return
        key = self._sort_key()
        if cols < 110:
            left = f" ↑↓ nav · Entrée · / chercher · f/t/a filtres · o tri: {key} · q quitter "
        else:
            left = (
                f" ↑↓ nav · Entrée détail · / chercher · f état · t proto · a risque"
                f" · c effacer · o tri: {key} · p pause · r relancer · q quitter "
            )
        right = f" {count} lignes "
        self._bar(height - 1, left, self.attr(5))
        if cols - len(right) - 1 > len(left) + 1:
            self._put(height - 1, cols - len(right) - 1, right, self.attr(5, True))

    # -- detail ----------------------------------------------------
    def draw_detail(self, height: int, cols: int) -> None:
        kind, obj = self.detail
        if kind == "app":
            self.draw_detail_app(obj, height, cols)
        elif kind == "domain":
            self.draw_detail_domain(obj, height, cols)
        else:
            self.draw_detail_session(obj, height, cols)

    def draw_detail_app(self, app: dict, height: int, cols: int) -> None:
        name = app["name"]
        pids = sorted(app["pids"])
        subtitle = f"{len(pids)} PID · {app['conns']} sessions · ↑{fbytes(app['tx'])} ↓{fbytes(app['rx'])}"
        self._header(height, cols, f"détail application — {name}  {subtitle}")

        sessions = [s for s in self.model.sessions if s.process == name]
        sessions.sort(key=lambda s: s.tx + s.rx, reverse=True)

        pids_text = ", ".join(str(p) for p in pids) or "-"
        self._put(1, 1, f"PID : {pids_text}", curses.A_DIM)
        y = 2
        command = self.model.procs.get(pids[0], "") if pids else ""
        if command:
            self._put(y, 1, "Commande : " + cut(command, cols - 13), curses.A_DIM)
            y += 1
        if sessions:
            owners = sorted({self.model.owner(s.uid) for s in sessions})
            exes = sorted({self.model.exe_for(s) for s in sessions if self.model.exe_for(s)})
            self._put(y, 1, "Utilisateur : " + cut(", ".join(owners), cols - 16), curses.A_DIM)
            y += 1
            self._put(y, 1, "Exécutable : " + cut(", ".join(exes) or "indisponible", cols - 15), curses.A_DIM)
            y += 1
        level = self.model.app_level(name)
        if level:
            self._put(y, 1, "Alerte : " + level, self.attr(LEVEL_COLORS[level], True))
            y += 1

        headers = [
            ("DIR", 6), ("DOMAINE / HÔTE", -1), ("DESTINATION", 22), ("SERVICE", 10),
            ("ÉTAT", 12), ("ÂGE", 7), ("↑", 8), ("↓", 8),
        ]
        top = y + 1
        rows = []
        for session in sessions:
            direction = self.model.direction(session)
            color = self.attr(2) if direction == "IN" else (
                curses.A_DIM if direction == "LOCAL" else self.attr(1)
            )
            cells = [
                ((direction, color),),
                ((cut(self.model.domain_for(session), 60),),),
                ((f"{session.remote_ip}:{session.remote_port}",),),
                ((self.model.service_for(session),),),
                ((state_label(session.state),),),
                ((fage(self.model.age(session)),),),
                ((fbytes(session.tx),),),
                ((fbytes(session.rx),),),
            ]
            rows.append((cells, ("session", session)))

        self.detail_rows = rows
        self.detail_offset = self.draw_table(
            top, height - 1, headers, rows, cols,
            offset=self.detail_offset, highlight=self.detail_sel,
        )
        self._put(height - 1, 1, " Échap/← retour · ↑↓ défiler · Entrée détail ", self.attr(5))
        if not sessions:
            self._put(top + 1, 2, "  Plus aucune session active — voir l'historique des sites ci-dessous", curses.A_DIM)
            sites = sorted(app["sites"], key=app["sites"].get, reverse=True)[:5]
            if sites:
                self._put(top + 3, 2, "Sites vus : " + ", ".join(sites), curses.A_DIM)

    def draw_detail_domain(self, item: dict, height: int, cols: int) -> None:
        self._header(
            height, cols,
            f"détail domaine — {item['name']}  {item['conns']} sessions · ↑{fbytes(item['tx'])} ↓{fbytes(item['rx'])}",
        )
        self._put(1, 1, "Applications : " + (", ".join(sorted(item["apps"])) or "-"), curses.A_DIM)
        headers = [
            ("APPLICATION", 18), ("DIR", 6), ("IP DISTANTE", 24), ("SERVICE", 10),
            ("ÉTAT", 12), ("↑", 9), ("↓", 9),
        ]
        sessions = []
        for session in self.model.sessions:
            if self.model.domain_for(session) == item["name"]:
                sessions.append(session)
        sessions.sort(key=lambda s: s.tx + s.rx, reverse=True)
        rows = []
        for session in sessions:
            direction = self.model.direction(session)
            color = self.attr(2) if direction == "IN" else (
                curses.A_DIM if direction == "LOCAL" else self.attr(1)
            )
            cells = [
                ((cut(session.process, 18),),),
                ((direction, color),),
                ((f"{session.remote_ip}:{session.remote_port}",),),
                ((self.model.service_for(session),),),
                ((state_label(session.state),),),
                ((fbytes(session.tx),),),
                ((fbytes(session.rx),),),
            ]
            rows.append((cells, ("session", session)))
        self.detail_rows = rows
        self.detail_offset = self.draw_table(
            3, height - 1, headers, rows, cols,
            offset=self.detail_offset, highlight=self.detail_sel,
        )
        self._put(height - 1, 1, " Échap/← retour · ↑↓ défiler · Entrée détail ", self.attr(5))

    def draw_detail_session(self, session: Session, height: int, cols: int) -> None:
        direction = self.model.direction(session)
        self._header(height, cols, f"détail session — {session.process} (PID {session.pid})")

        lines = [
            ("Direction", direction),
            ("Protocole", f"{session.proto.upper()} / {self.model.service_for(session)}"),
            ("Local", f"{session.local_ip}:{session.local_port}" + (f" ({session.iface})" if session.iface else "")),
            ("Distant", f"{session.remote_ip}:{session.remote_port}"),
            ("Domaine", self.model.domain_for(session)),
            ("Portée", self.model.scope(session)),
            ("État", state_label(session.state)),
            ("Octets envoyés", fbytes(session.tx)),
            ("Octets reçus", fbytes(session.rx)),
            ("RTT", f"{session.rtt:.1f} ms" if session.rtt else "-"),
            ("Âge", fage(self.model.age(session))),
            ("Dernière activité", "à l'instant" if self.model.idle(session) < 2
             else f"il y a {fage(self.model.idle(session))}"),
            ("UID", str(session.uid) if session.uid >= 0 else "-"),
            ("Utilisateur", self.model.owner(session.uid)),
            ("Exécutable", self.model.exe_for(session)
             or ("indisponible" if session.pid > 0 else "-")),
        ]
        command = self.model.procs.get(session.pid, "")
        if command:
            lines.append(("Commande", command))

        y = 2
        for label, value in lines:
            if y >= height - 2:
                break
            self._put(y, 2, f"{label:<18}", self.attr(5, True))
            self._put(y, 21, cut(str(value), cols - 23))
            y += 1

        alerts = self.model.alerts_of(session) + self.model.app_alerts.get(session.process, [])
        if alerts and y < height - 2:
            y += 1
            self._put(
                y, 2,
                f"ALERTES ({len(alerts)}) — indices à vérifier, pas une preuve d'intrusion",
                self.attr(5, True),
            )
            y += 1
            for alert in alerts:
                if y >= height - 2:
                    break
                self._put(
                    y, 4, cut(f"[{alert.level.upper()}] {alert.reason}", cols - 6),
                    self.attr(LEVEL_COLORS[alert.level], True),
                )
                y += 1
                if y >= height - 2:
                    break
                self._put(y, 7, cut("→ " + alert.advice, cols - 9), curses.A_DIM)
                y += 1

        self._put(height - 1, 1, " Échap/← retour · q quitter ", self.attr(5))

    # -- input -----------------------------------------------------
    def prompt(self, label: str) -> str:
        height, cols = self.stdscr.getmaxyx()
        text = ""
        cursor = 0
        curses.curs_set(1)
        while True:
            self._bar(height - 1, f" {label}{text}", self.attr(3))
            self._put(height - 1, 2 + len(label) + cursor, " ")
            self.stdscr.refresh()
            ch = self.stdscr.getch()
            if ch in (10, 13, curses.KEY_ENTER):
                break
            if ch == 27:
                text = ""
                break
            if ch in (curses.KEY_BACKSPACE, 127, 8):
                text = text[:-1]
                cursor = max(0, cursor - 1)
            elif 32 <= ch < 127:
                text += chr(ch)
                cursor += 1
            elif ch == curses.KEY_RESIZE:
                height, cols = self.stdscr.getmaxyx()
        curses.curs_set(0)
        return text

    def handle(self, ch: int) -> None:
        if ch == -1:
            return
        if ch in (ord("q"), 3):
            self.running = False
            return

        if self.detail:
            if ch in (27, curses.KEY_LEFT, ord("q"), 3):
                if ch in (ord("q"), 3):
                    self.running = False
                else:
                    self.detail = None
                    self.detail_sel = 0
                    self.detail_offset = 0
                return
            total = len(getattr(self, "detail_rows", []))
            if ch in (curses.KEY_DOWN, ord("j")):
                self.detail_sel = min(max(0, total - 1), self.detail_sel + 1)
            elif ch in (curses.KEY_UP, ord("k")):
                self.detail_sel = max(0, self.detail_sel - 1)
            elif ch == curses.KEY_NPAGE:
                self.detail_sel = min(max(0, total - 1), self.detail_sel + 10)
            elif ch == curses.KEY_PPAGE:
                self.detail_sel = max(0, self.detail_sel - 10)
            elif ch == curses.KEY_HOME:
                self.detail_sel = 0
            elif ch == curses.KEY_END:
                self.detail_sel = max(0, total - 1)
            elif ch in (10, 13, curses.KEY_ENTER, curses.KEY_RIGHT, ord("d")):
                if self.detail[0] != "session" and total:
                    try:
                        _cells, obj = self.detail_rows[self.detail_sel]
                        if obj[0] == "session":
                            self.detail = ("session", obj[1])
                            self.detail_sel = 0
                            self.detail_offset = 0
                    except IndexError:
                        pass
            return

        if ch in (ord("1"), ord("2"), ord("3"), ord("4"), ord("5")):
            self.tab = int(chr(ch)) - 1
            self.sel = 0
            self.offset = 0
            return
        if ch == ord("/"):
            self.filter = self.prompt("filtrer: ")
            self.sel = 0
            self.offset = 0
            return
        if ch in (27, ord("c")):
            self.filter = ""
            self.state_filter = ""
            self.proto_filter = ""
            self.risk_filter = ""
            self.sel = 0
            self.offset = 0
            return
        if ch == ord("f"):
            self.state_filter = STATE_FILTERS[
                (STATE_FILTERS.index(self.state_filter) + 1) % len(STATE_FILTERS)]
            self.sel = 0
            self.offset = 0
            return
        if ch == ord("t"):
            self.proto_filter = PROTO_FILTERS[
                (PROTO_FILTERS.index(self.proto_filter) + 1) % len(PROTO_FILTERS)]
            self.sel = 0
            self.offset = 0
            return
        if ch == ord("a"):
            self.risk_filter = RISK_FILTERS[
                (RISK_FILTERS.index(self.risk_filter) + 1) % len(RISK_FILTERS)]
            self.sel = 0
            self.offset = 0
            return
        if ch == ord("o"):
            self.sort_index[self.tab] = (self.sort_index[self.tab] + 1) % len(SORTS[self.tab])
            self.sel = 0
            self.offset = 0
            return
        if ch == ord("p"):
            self.model.paused = not self.model.paused
            return
        if ch == ord("r"):
            self.restart()
            return

        _headers, rows = self.current_view(self.stdscr.getmaxyx()[1])
        if ch in (curses.KEY_DOWN, ord("j")):
            self.sel = min(len(rows) - 1, self.sel + 1)
        elif ch in (curses.KEY_UP, ord("k")):
            self.sel = max(0, self.sel - 1)
        elif ch == curses.KEY_NPAGE:
            self.sel = min(len(rows) - 1, self.sel + 10)
        elif ch == curses.KEY_PPAGE:
            self.sel = max(0, self.sel - 10)
        elif ch == curses.KEY_HOME:
            self.sel = 0
        elif ch == curses.KEY_END:
            self.sel = max(0, len(rows) - 1)
        elif ch in (10, 13, curses.KEY_ENTER, curses.KEY_RIGHT, ord("d")):
            if rows:
                self.sel = min(self.sel, len(rows) - 1)
                _cells, obj = rows[self.sel]
                self.detail = (obj[0], obj[1])
                self.detail_sel = 0
                self.detail_offset = 0
                self.status = ""

    # -- lifecycle -------------------------------------------------
    def restart(self) -> None:
        self.collector.stop()
        self.collector = Collector()
        self.model = Model()
        self.sel = 0
        self.offset = 0
        self.detail = None
        self.detail_sel = 0
        self.detail_offset = 0
        try:
            self.collector.start()
        except OSError as exc:
            self.fatal = str(exc)

    def run(self) -> int:
        self.setup()
        try:
            self.collector.start()
        except OSError as exc:
            self.fatal = f"Impossible de lancer le collecteur: {exc}"

        try:
            while self.running:
                drained = 0
                while drained < 500:
                    try:
                        message = self.collector.queue.get_nowait()
                    except queue.Empty:
                        break
                    self.model.apply(message)
                    drained += 1
                if self.model.error is None and self.collector.proc and self.collector.proc.poll() is not None:
                    self.model.error = (
                        self.collector.stderr[-1]
                        if self.collector.stderr
                        else "collecteur arrêté (r pour relancer)"
                    )
                try:
                    self.draw()
                    self.handle(self.stdscr.getch())
                except Exception as exc:  # affichage : on ne tue pas l'app
                    import traceback
                    with open("/tmp/fwmon-err.log", "a") as _f:
                        _f.write(traceback.format_exc() + "\n")
                    self.model.error = f"{type(exc).__name__}: {exc}"
                    time.sleep(0.2)
        finally:
            # Toujours tuer le collecteur root, meme sur SIGTERM / SIGHUP / Ctrl-C.
            self.collector.stop()
        return 0


def main(argv: list[str] | None = None) -> int:
    locale.setlocale(locale.LC_ALL, "")
    if argv is None:
        argv = sys.argv[1:]
    if "-h" in argv or "--help" in argv:
        print("fwmon — surveillance réseau par application (lecture seule)\n")
        print("Lance l'interface. Le collecteur est démarré via sudox ou sudo (root requis).")
        return 0

    def _terminate(_signum, _frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, _terminate)
    signal.signal(signal.SIGHUP, _terminate)

    env = os.environ
    if not env.get("ESCDELAY"):
        os.environ["ESCDELAY"] = "25"
    try:
        return curses.wrapper(lambda screen: UI(screen).run())
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    sys.exit(main())
