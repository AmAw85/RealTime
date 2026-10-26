# fwmon — per-application network monitoring

[Français](README.md) · **English** · [العربية](README.ar.md)

A small terminal tool in the spirit of a firewall appliance (Fortinet / FortiView):
it shows in real time **what each application is doing on the network** — sessions,
traffic direction (IN / OUT / LOCAL), throughput, contacted sites, listening ports.

> The interface itself is in French (labels, alerts and recommendations). This README
> documents it in English.

```
  fwmon · Surveillance réseau   14:12:34   [root]   7 applis · 153 sessions · ↑40.6 Mo ↓31.2 Mo · ⚠ 3 alertes
  1:Applications   2:Connexions   3:Domaines   4:Entrant   5:Alertes (3)
 APPLICATION        PID     CONN  ↑ ENVOYÉ   ↓ REÇU     ALERTE  ACTIVITÉ
 opencode           41801   8     37.6 Mo    28.7 Mo    moyen   HTTPS · 172.65.90.20
 chrome             6948    27    256.2 Ko   945.8 Ko   -       HTTPS · 104.18.32.47
 script.sh          22914   1     1.2 Ko     0 o        élevé   TCP · 203.0.113.7
```

## What it does

- **Applications**: one row per application (grouped by process name) with the number of
  sessions, bytes sent / received and a summary of its activity (main service + contacted
  hosts).
- **Connexions** (Connections): every TCP/UDP session with PID, direction (IN / OUT /
  LOCAL), remote host, service, state, owning user, activity ("actif" or time since the
  last byte exchanged) and the **risk level**. Rows idle for more than a minute are dimmed.
- **Alertes** (Alerts): detected clues, grouped by rule / application / reason, with the
  level, the number of affected sessions and a recommendation.
- **Domaines** (Domains): contacted sites (passive DNS + TLS SNI + reverse lookup), the
  applications involved and the traffic exchanged.
- **Entrant** (Inbound): inbound connections and listening ports.
- **Enter / d**: detail view (sessions of an application with user and executable; then a
  full session card: PID, user, executable, exact command line, interface, RTT, age, last
  activity, bytes, UID, and alerts with their recommendation).

## Alerts — clues, not proof

Each alert shows a level (**faible**, **moyen**, **élevé** — low, medium, high), the
application and connection involved, the precise reason and a recommendation. The rules
are simple and explainable, computed locally from already collected data:

| Rule | Level | Trigger |
|---|---|---|
| unknown process | low | socket without PID (kernel, or unprivileged collection) |
| executable unavailable | low | process alive but its executable path is unreadable |
| executable outside system paths | medium | binary outside `/usr`, `/opt`, `/snap`, `/var/lib/flatpak`… |
| suspicious executable | high | binary started from `/tmp`, `/var/tmp`, `/dev/shm`, `/run/user` |
| sensitive service | medium | outbound traffic leaving the local network to FTP, TELNET, SMB, RDP, VNC, databases… |
| unusual port | low | remote port with no well-known service (established connection) |
| inbound from WAN | medium | established inbound connection from outside the local network |
| connection count | medium / high | more than 120 / 300 simultaneous connections for one application |
| repeated attempts | medium / high | 8 connections (4 in SYN) to the same destination within 60 s |

An unknown domain is **never** considered suspicious on its own: without a resolved name
the IP is displayed, and a missing name is not an alert. Thresholds are guidelines, not
truth — an alert calls for a check (the recommendations give the command to run).
**fwmon never stops a process and never blocks a connection**, and sends no data outside.

## How it works

- The interface runs **as a normal user**.
- A single **privileged collector** is started on launch through `sudox` (or `sudo -n` as a
  fallback). It reads `ss -tunapie`, `/proc/<pid>/cmdline`, `/proc/<pid>/exe`, `ip addr`
  and passively captures DNS (port 53) and TLS ClientHello (SNI, port 443) with an
  in-kernel BPF filter. Without privileges the tool still starts, in restricted mode, and
  clearly reports the missing information instead of inventing data.
- **Alerts** are computed by the interface, in memory, from that stream; no external call,
  no file, no database.
- The collector writes **NDJSON on its standard output**; the interface displays it.
- **Read-only**: no packet is modified, dropped or injected. No firewall rule is touched,
  no process is stopped, no connection is blocked.
- **Nothing leaves the machine**: all processing (including alerts) is local, and nothing is
  written to disk — no history, no database.

## Requirements

- Linux, Python 3.10+ (tested on Ubuntu 26.04 / Python 3.14), `ss` (`iproute2` package).
- `sudo` for privileged collection. fwmon uses `sudox` (`~/.local/bin/sudox`, non-interactive
  askpass) when available, otherwise `sudo -n` if the session is already unlocked
  (`sudo -v`). Without privileges the tool still starts in restricted mode and says so.
- `screen` for the desktop shortcuts and `fwmonctl` (optional).
- A UTF-8 terminal (arrows ↑ ↓ and accented characters are used).

## Installation

```sh
cd ~/fwmon
./install.sh              # creates ~/.local/bin/fwmon (symlink)
```

Then:

```sh
fwmon
```

or directly:

```sh
./fwmon.sh
```

## Desktop shortcuts (menu + desktop)

```sh
./shortcuts.sh
```

Installs three shortcuts in the **Applications** menu and on the **Desktop**:

| Shortcut | Effect |
|---|---|
| **fwmon — Lancer la surveillance** | starts fwmon in a terminal window |
| **fwmon — Afficher** | reopens the window (the application keeps running in the background) |
| **fwmon — Fermer** | stops the application **and** its root collector |

Same actions from the command line:

```sh
fwmonctl start | show | stop | status      # start | show | stop | state
```

fwmon runs in a detached `screen` session: closing the window does not stop it,
"Afficher" reopens it, "Fermer" stops it cleanly (the root collector is terminated in
every case, including on `SIGTERM`/`SIGHUP`).

To remove the shortcuts:

```sh
rm ~/.local/share/applications/fwmon-*.desktop ~/Desktop/fwmon-*.desktop
```

## Keys

| Key | Action |
|---|---|
| `1` … `5` | switch tab |
| `↑` `↓` / `k` `j` | navigate |
| `PgUp` / `PgDn` / `Home` / `End` | fast scrolling |
| `Enter` / `d` / `→` | open details |
| `Esc` / `←` | go back |
| `/` | search (application, PID, domain, IP, port, protocol, state, user) |
| `f` | state filter: all → established → other |
| `t` | protocol filter: all → tcp → udp |
| `a` | risk filter: all → medium+ → high |
| `Esc` or `c` | clear the search and all filters |
| `o` | change sort order (traffic, name, destination, risk…) |
| `p` | pause / resume display updates |
| `r` | restart the collector |
| `q` | quit |

## Known limitations

- **Chrome / Firefox** often use DNS-over-HTTPS and, increasingly, ECH (Encrypted Client
  Hello): the site name is then not visible and the IP is displayed (with the PTR name when
  it exists).
- **QUIC (UDP 443)** also encrypts SNI; only TCP/TLS sessions are decoded.
- **Byte counters** come from `ss`: they are only available for TCP (UDP shows `-`).
- Sockets with no visible process (Docker NAT, kernel) appear as `(noyau)` (kernel) or with
  the UID owner's name, along with the "unknown process" alert.
- The executable path requires reading `/proc/<pid>/exe`: without privileges it is shown as
  "indisponible" (unavailable). PIDs are tracked together with their kernel start time,
  which avoids attributing a connection to a reused PID.
- Alerts are **heuristics**: false positives are possible (browsers, P2P, sync clients), and
  some cases are undetectable (DoH/ECH/QUIC, encrypted traffic, compromised system binary).
- History is in memory only: quitting the tool clears it.

## Troubleshooting

- `[utilisateur]` instead of `[root]` in the header: `sudox` was not found or failed. Check
  `sudox true`, or unlock sudo first with `sudo -v`.
- `ERREUR : …` in the footer: the collector stopped; press `r` to restart it.
- No domain displayed while traffic exists: the BPF filter could not be installed (rare);
  restart with `r`. Also check that the traffic is not QUIC/ECH.

## License

MIT — see [LICENSE](LICENSE). Provided as is, without warranty: alerts are clues to
verify, not a certified security tool.
