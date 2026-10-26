# fwmon — surveillance réseau par application

**Français** · [English](README.en.md) · [العربية](README.ar.md)

Petit outil en terminal, dans l'esprit d'une appliance pare-feu (Fortinet / FortiView) :
il montre en temps réel **ce que chaque application fait sur le réseau** — sessions,
sens du trafic (IN / OUT / LOCAL), débits, sites contactés, ports en écoute.

```
  fwmon · Surveillance réseau   14:12:34   [root]   7 applis · 153 sessions · ↑40.6 Mo ↓31.2 Mo · ⚠ 3 alertes
  1:Applications   2:Connexions   3:Domaines   4:Entrant   5:Alertes (3)
 APPLICATION        PID     CONN  ↑ ENVOYÉ   ↓ REÇU     ALERTE  ACTIVITÉ
 opencode           41801   8     37.6 Mo    28.7 Mo    moyen   HTTPS · 172.65.90.20
 chrome             6948    27    256.2 Ko   945.8 Ko   -       HTTPS · 104.18.32.47
 script.sh          22914   1     1.2 Ko     0 o        élevé   TCP · 203.0.113.7
```

## Ce que ça fait

- **Applications** : une ligne par application (regroupée par nom de processus), avec le
  nombre de sessions, les octets envoyés / reçus et une synthèse de son activité
  (service principal + sites contactés).
- **Connexions** : toutes les sessions TCP/UDP, avec le PID, le sens (IN / OUT / LOCAL),
  l'hôte distant, le service, l'état, l'utilisateur propriétaire, l'activité
  (« actif » ou temps depuis le dernier octet échangé) et le **niveau de risque**.
  Les lignes inactives depuis plus d'une minute sont grisées.
- **Alertes** : les indices détectés, groupés par règle / application / raison, avec le
  niveau, le nombre de sessions concernées et une recommandation de vérification.
- **Domaines** : les sites contactés (DNS passif + SNI TLS + résolution inverse), les
  applications concernées et le volume échangé.
- **Entrant** : les connexions entrantes et les ports en écoute.
- **Entrée / d** : vue détaillée (liste des sessions d'une application avec utilisateur et
  exécutable ; puis fiche complète d'une session : PID, utilisateur, exécutable, commande
  exacte, interface, RTT, âge, dernière activité, octets, UID, et alertes avec leur
  recommandation).

## Alertes — des indices, pas des preuves

Chaque alerte affiche un niveau (**faible**, **moyen**, **élevé**), l'application et la
connexion concernées, la raison précise et une recommandation. Les règles sont simples et
explicables, calculées localement à partir des données déjà collectées :

| Règle | Niveau | Déclencheur |
|---|---|---|
| processus inconnu | faible | socket sans PID (noyau, ou collecte sans privilèges) |
| exe indisponible | faible | processus vivant mais chemin d'exécutable illisible |
| exe hors système | moyen | binaire hors `/usr`, `/opt`, `/snap`, `/var/lib/flatpak`… |
| exe suspect | élevé | binaire lancé depuis `/tmp`, `/var/tmp`, `/dev/shm`, `/run/user` |
| service sensible | moyen | sortie hors réseau local vers FTP, TELNET, SMB, RDP, VNC, bases… |
| port inhabituel | faible | port distant sans service standard connu (connexion établie) |
| entrant WAN | moyen | connexion entrante établie depuis l'extérieur du réseau local |
| nb connexions | moyen / élevé | plus de 120 / 300 connexions simultanées pour une application |
| tentatives répétées | moyen / élevé | 8 connexions (4 en SYN) vers la même destination en 60 s |

Un domaine inconnu n'est **jamais** considéré comme suspect à lui seul : sans nom résolu
on affiche l'IP, et l'absence de nom n'est pas une alerte. Les seuils sont des repères,
pas des vérités — une alerte demande une vérification (les recommandations donnent la
commande à lancer). **fwmon n'arrête aucun processus et ne bloque aucune connexion**, et
n'envoie aucune donnée à l'extérieur.

## Principe

- L'interface tourne **en tant qu'utilisateur normal**.
- Un **collecteur privilégié** unique est lancé au démarrage via `sudox` (ou `sudo` en
  secours). Il lit `ss -tunapie`, `/proc/<pid>/cmdline`, `/proc/<pid>/exe`, `ip addr` et
  capture en passif le DNS (port 53) et les ClientHello TLS (SNI, port 443) avec un filtre
  BPF dans le noyau. Sans privilèges, l'outil démarre quand même et signale les
  informations manquantes au lieu d'inventer des données.
- Les **alertes** sont calculées côté interface, en mémoire, à partir de ce flux ; aucun
  appel externe, aucun fichier, aucune base de données.
- Le collecteur écrit du **NDJSON sur sa sortie standard** ; l'interface l'affiche.
- **Lecture seule** : aucun paquet n'est modifié, bloqué ou injecté. Aucune règle de
  pare-feu n'est touchée, aucun processus n'est arrêté, aucune connexion n'est bloquée.
- **Aucun envoi vers l'extérieur** : le traitement (dont les alertes) est local, et rien
  n'est écrit sur disque — pas d'historique, pas de base de données.

## Prérequis

- Linux, Python 3.10+ (testé sur Ubuntu 26.04 / Python 3.14), `ss` (paquet `iproute2`).
- `sudo` pour la collecte privilégiée. fwmon utilise `sudox` (`~/.local/bin/sudox`,
  askpass non interactif) s'il est présent, sinon `sudo -n` si la session est déjà
  déverrouillée (`sudo -v`). Sans privilèges l'outil démarre quand même, en mode
  restreint, et l'indique clairement.
- `screen` pour les raccourcis et `fwmonctl` (facultatif).
- Un terminal UTF-8 (les flèches ↑ ↓ et les accents sont utilisés).

## Installation

```sh
cd ~/fwmon
./install.sh              # crée ~/.local/bin/fwmon (lien symbolique)
```

Puis :

```sh
fwmon
```

ou directement :

```sh
./fwmon.sh
```

## Raccourcis (menu + Bureau)

```sh
./shortcuts.sh
```

Installe trois raccourcis dans le menu **Applications** et sur le **Bureau** :

| Raccourci | Effet |
|---|---|
| **fwmon — Lancer la surveillance** | démarre fwmon dans une fenêtre de terminal |
| **fwmon — Afficher** | rouvre la fenêtre (l'application continue de tourner en arrière-plan) |
| **fwmon — Fermer** | arrête l'application **et** son collecteur root |

Les mêmes actions en ligne de commande :

```sh
fwmonctl start | show | stop | status      # lancer | afficher | fermer | etat
```

fwmon tourne dans une session `screen` détachée : fermer la fenêtre ne l'arrête
pas, « Afficher » la rouvre, « Fermer » l'arrête proprement (le collecteur root
est terminé dans tous les cas, y compris sur `SIGTERM`/`SIGHUP`).

Pour désinstaller les raccourcis :

```sh
rm ~/.local/share/applications/fwmon-*.desktop ~/Desktop/fwmon-*.desktop
```

## Touches

| Touche | Action |
|---|---|
| `1` … `5` | changer d'onglet |
| `↑` `↓` / `k` `j` | naviguer |
| `PgUp` / `PgDn` / `Home` / `End` | défilement rapide |
| `Entrée` / `d` / `→` | ouvrir le détail |
| `Échap` / `←` | revenir |
| `/` | chercher (application, PID, domaine, IP, port, protocole, état, utilisateur) |
| `f` | filtre état : toutes → établies → autres |
| `t` | filtre protocole : tous → tcp → udp |
| `a` | filtre risque : tous → moyen+ → élevé |
| `Échap` ou `c` | effacer la recherche et tous les filtres |
| `o` | changer le tri (trafic, nom, destination, risque…) |
| `p` | pause / reprise de l'affichage |
| `r` | relancer le collecteur |
| `q` | quitter |

## Limites connues

- **Chrome / Firefox** utilisent souvent DNS-over-HTTPS et, de plus en plus, ECH
  (Encrypted Client Hello) : le nom du site n'est alors pas visible, on affiche l'IP
  (avec le nom PTR quand il existe).
- **QUIC (UDP 443)** chiffre aussi le SNI ; seules les sessions TCP/TLS sont décodées.
- Les **octets** proviennent de `ss` : ils ne sont disponibles que pour TCP (UDP affiche `-`).
- Les sockets sans processus visible (NAT Docker, noyau) apparaissent sous le nom
  `(noyau)` ou le nom du propriétaire de l'UID, avec l'alerte « processus inconnu ».
- Le chemin d'exécutable exige la lecture de `/proc/<pid>/exe` : sans privilèges il est
  affiché « indisponible ». Le PID est suivi avec son heure de démarrage dans le noyau,
  ce qui évite d'attribuer une connexion à un PID réutilisé.
- Les alertes sont des **heuristiques** : faux positifs possibles (navigateurs, P2P,
  synchronisation), et certains cas ne sont pas détectables (DoH/ECH/QUIC, trafic
  chiffré, binaire système compromis).
- L'historique est en mémoire : quitter l'outil le vide.

## Dépannage

- `[utilisateur]` au lieu de `[root]` dans l'en-tête : `sudox` n'a pas été trouvé ou a
  échoué. Vérifier `sudox true`.
- `ERREUR : …` dans le pied de page : le collecteur s'est arrêté ; `r` pour le relancer.
- Aucun domaine affiché alors que le trafic existe : le filtre BPF n'a pas pu être posé
  (rare) ; relancer avec `r`. Vérifier aussi que le trafic n'est pas en QUIC/ECH.

## Licence

MIT — voir [LICENSE](LICENSE). Fourni tel quel, sans garantie : les alertes sont des
indices à vérifier, pas un outil de sécurité certifié.
