---
name: navmax-scanner
description: NavMAX Scanner — reconnaissance réseau TCP connect, UDP, Nmap wrapper, Nuclei scanner, fingerprinting OS/service, scan contextuel et base de vulnérabilités.
metadata:
  subdomain: scanner
  when_to_use: "navmax scanner reconnaissance network tcp connect udp nmap nuclei fingerprint os service contextual vulnerability"
  navmax_module: decepticon.navmax.scanner
  mitre_attack:
    - T1046
    - T1040
---

# NavMAX Scanner Wrapper

## Module : `decepticon.navmax.scanner`

Reconnaissance réseau complète : TCP Connect Scan, Nmap wrapper,
Nuclei, fingerprinting OS/service, scanner contextuel.

## Classes & utilitaires exposés

| Classe / Fonction | Rôle |
|---|---|
| `tcp_connect_scan` | TCP Connect Scan standard (sans privilèges) |
| `run_scan` / `run_scan_background` | Scan complet avec engine (TCP + service detection) |
| `parse_ports` | Parsing de chaîne de ports (ex: "22,80,100-200") |
| `detect_os` | Fingerprinting OS basé sur TTL et flags TCP |
| `detect_service` | Détection de service (banner grabbing) |
| `NucleiScanner` | Scanner de vulnérabilités Nuclei (YAML templates) |
| `NucleiFinding` | Résultat de scan Nuclei |
| `ContextualScanner` | Scan contextuel adaptatif selon la cible |
| `VulnDB` | Base de vulnérabilités locale |

## Workflow typique

```python
from decepticon.navmax.scanner import (
    tcp_connect_scan,
    run_scan,
    detect_service,
    detect_os,
    NucleiScanner,
)

# 1. TCP scan rapide
ports = tcp_connect_scan("192.168.1.100", ports=[22, 80, 443, 8080], timeout=3)
for port in ports:
    print(f"Port {port.port}: {port.state}")

# 2. Scan complet avec détection de service
results = run_scan("192.168.1.100", ports="1-1024")
for r in results:
    service = detect_service(r.port, r.banner)
    print(f"{r.port}/tcp → {service}")

# 3. Fingerprinting
os_info = detect_os(ttl=128, window_size=65535)
print(f"OS probable: {os_info}")

# 4. Nuclei
nuclei = NucleiScanner()
findings = nuclei.scan_target("https://192.168.1.100:443")
for f in findings:
    print(f.severity, f.name, f.remediation)
```

## Dépendances

- `nuclei` (binaire système, optionnel)
- `nmap` (binaire système, optionnel pour NmapScanner)
- `scapy` (optionnel, pour TCP raw)
