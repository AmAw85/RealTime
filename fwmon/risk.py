"""Indices de connexion suspects, calcules localement.

Aucune donnee ne sort de la machine : ce module ne fait qu'appliquer des
regles explicables aux informations deja collectees. Une alerte est un
indice a examiner, jamais une preuve d'intrusion.
"""

from __future__ import annotations

from dataclasses import dataclass

from fwmon.ports import SERVICES

LEVELS = ("faible", "moyen", "élevé")
_RANK = {name: index for index, name in enumerate(LEVELS)}

# Emplacements systeme ou un binaire est attendu.
TRUSTED_PREFIXES = (
    "/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/",
    "/usr/lib/", "/usr/libexec/", "/usr/local/bin/", "/usr/local/sbin/",
    "/usr/share/", "/snap/", "/opt/", "/var/lib/flatpak/", "/app/",
)

# Emplacements ou un binaire executable est inhabituel.
SUSPECT_PREFIXES = ("/tmp/", "/var/tmp/", "/dev/shm/", "/run/user/")

# Services sensibles exposes hors du reseau local.
SENSITIVE_PORTS = {
    21: "FTP", 23: "TELNET", 445: "SMB", 1433: "MSSQL", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
    11211: "Memcached", 27017: "MongoDB",
}

MANY_CONNS_MEDIUM = 120
MANY_CONNS_HIGH = 300
REPEAT_WINDOW = 60
REPEAT_MEDIUM = 8
REPEAT_SYN = 4


@dataclass(slots=True)
class Alert:
    code: str
    level: str
    reason: str
    advice: str


@dataclass(slots=True)
class Context:
    process: str = "-"
    pid: int = 0
    owner: str = "-"
    exe: str = ""
    exe_known: bool = False
    direction: str = "OUT"
    scope: str = "WAN"
    proto: str = "tcp"
    local_port: int = 0
    remote_port: int = 0
    state: str = ""
    domain: str = ""
    conns_for_app: int = 0
    repeats: int = 0


def level_rank(level: str) -> int:
    return _RANK.get(level, -1)


def worst(alerts: list[Alert]) -> str:
    best = ""
    for alert in alerts:
        if not best or level_rank(alert.level) > level_rank(best):
            best = alert.level
    return best


def _exe_alert(ctx: Context) -> Alert | None:
    if not ctx.exe:
        return None
    if ctx.exe.startswith(SUSPECT_PREFIXES):
        return Alert(
            "exe_suspect", "élevé",
            f"exécutable dans un emplacement inhabituel : {ctx.exe}",
            f"vérifier l'origine du binaire : ls -l {ctx.exe} ; dpkg -S {ctx.exe}",
        )
    if not ctx.exe.startswith(TRUSTED_PREFIXES):
        return Alert(
            "exe_hors_systeme", "moyen",
            f"exécutable hors emplacement système : {ctx.exe}",
            f"vérifier l'origine du binaire : ls -l {ctx.exe} ; dpkg -S {ctx.exe}",
        )
    return None


def evaluate(ctx: Context) -> list[Alert]:
    alerts: list[Alert] = []

    if ctx.pid <= 0:
        alerts.append(Alert(
            "processus_inconnu", "faible",
            f"socket {ctx.proto} sans processus identifiable",
            "relancer fwmon via sudox ; vérifier la socket avec : ss -tunapie",
        ))
    elif ctx.exe_known and not ctx.exe:
        alerts.append(Alert(
            "exe_indisponible", "faible",
            f"chemin de l'exécutable indisponible pour le PID {ctx.pid}",
            f"vérifier que le processus existe encore : ps -p {ctx.pid} -o pid,comm",
        ))

    if ctx.pid > 0:
        exe_alert = _exe_alert(ctx)
        if exe_alert:
            alerts.append(exe_alert)

    if ctx.direction == "OUT" and ctx.scope == "WAN":
        if ctx.remote_port in SENSITIVE_PORTS:
            name = SENSITIVE_PORTS[ctx.remote_port]
            alerts.append(Alert(
                "service_sensible", "moyen",
                f"connexion sortante vers {name} (port {ctx.remote_port})"
                f" hors réseau local, vers {ctx.domain or '-'}",
                "vérifier que ce service est attendu ; un protocole non chiffré"
                " peut exposer les identifiants",
            ))
        elif ctx.state == "ESTAB" and ctx.remote_port and ctx.remote_port not in _STANDARD_PORTS:
            alerts.append(Alert(
                "port_inhabituel", "faible",
                f"port distant inhabituel {ctx.remote_port} vers {ctx.domain or ctx.remote_port}",
                f"vérifier le service associé : ss -tnp | grep {ctx.remote_port}",
            ))

    if ctx.direction == "IN" and ctx.scope == "WAN":
        alerts.append(Alert(
            "entrant_wan", "moyen",
            f"connexion entrante depuis {ctx.domain or '-'} vers le port local {ctx.local_port}",
            f"vérifier le service en écoute : ss -tlnp | grep {ctx.local_port}",
        ))

    if ctx.conns_for_app >= MANY_CONNS_HIGH:
        alerts.append(Alert(
            "connexions_nombreuses", "élevé",
            f"{ctx.conns_for_app} connexions simultanées pour {ctx.process}",
            "vérifier s'il s'agit d'un navigateur, d'un client P2P ou d'une"
            " synchronisation ; inspecter les destinations",
        ))
    elif ctx.conns_for_app >= MANY_CONNS_MEDIUM:
        alerts.append(Alert(
            "connexions_nombreuses", "moyen",
            f"{ctx.conns_for_app} connexions simultanées pour {ctx.process}",
            "vérifier s'il s'agit d'un navigateur, d'un client P2P ou d'une"
            " synchronisation ; inspecter les destinations",
        ))

    if ctx.repeats >= REPEAT_SYN and ctx.state in ("SYN-SENT", "SYN-RECV"):
        alerts.append(Alert(
            "tentatives_repetees", "élevé",
            f"{ctx.repeats} tentatives vers {ctx.domain or '-'}:{ctx.remote_port}"
            f" en moins de {REPEAT_WINDOW} s (connexion non établie)",
            "vérifier la destination et le service visé ; un balayage de ports"
            " produit ce comportement",
        ))
    elif ctx.repeats >= REPEAT_MEDIUM:
        alerts.append(Alert(
            "tentatives_repetees", "moyen",
            f"{ctx.repeats} connexions vers {ctx.domain or '-'}:{ctx.remote_port}"
            f" en moins de {REPEAT_WINDOW} s",
            "vérifier si ce rythme est normal pour cette application",
        ))

    return alerts


_STANDARD_PORTS = frozenset(SERVICES)
