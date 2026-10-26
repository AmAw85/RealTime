"""Ports de service connus (IANA / usages courants)."""

SERVICES = {
    20: "FTP", 21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP", 53: "DNS",
    67: "DHCP", 68: "DHCP", 80: "HTTP", 110: "POP3", 123: "NTP", 137: "NETBIOS",
    139: "SMB", 143: "IMAP", 161: "SNMP", 389: "LDAP", 443: "HTTPS", 445: "SMB",
    465: "SMTPS", 514: "SYSLOG", 587: "SMTP", 631: "IPP", 636: "LDAPS",
    853: "DoT", 873: "RSYNC", 993: "IMAPS", 995: "POP3S", 1194: "VPN",
    1900: "SSDP", 2083: "HTTPS", 3306: "MySQL", 3478: "STUN", 5060: "SIP",
    5222: "XMPP", 5223: "XMPP", 5228: "GCM", 5353: "mDNS", 5432: "Postgres",
    6379: "Redis", 8080: "HTTP-alt", 8443: "HTTPS-alt", 8883: "MQTT",
    27017: "MongoDB", 51820: "WireGuard",
}
