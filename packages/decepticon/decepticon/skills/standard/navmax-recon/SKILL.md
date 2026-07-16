---
name: navmax-recon
description: NavMAX Recon — OSINT multi-source (DNS, WHOIS, SSL, Shodan, Censys, Web scraping), graphe d'entités Maltego-like, orchestrateur d'investigation, proxy MITM, fuzzer et web scanner.
metadata:
  subdomain: osint
  when_to_use: "navmax recon osint dns whois ssl shodan censys web scraping graph entity maltego investigation proxy mitm fuzzer intruder"
  navmax_module: decepticon.navmax.osint
  mitre_attack:
    - T1590
    - T1591
    - T1592
    - T1595
    - T1596
    - T1598
---

# NavMAX Recon Wrapper

## Modules : `decepticon.navmax.osint`, `decepticon.navmax.proxy`

Deux modules combinés pour la reconnaissance complète et l'interception web.

### Partie 1 — OSINT (`decepticon.navmax.osint`)

| Classe / Fonction | Rôle |
|---|---|
| `DnsCollector` | Collecte DNS (A, AAAA, MX, NS, TXT, SOA, CNAME, zone transfer) |
| `WhoisCollector` | Recherche WHOIS (domaine, IP, ASN) |
| `SslCollector` | Analyse de certificats SSL/TLS |
| `WebCollector` | Web scraping et fingerprinting technologique (Wappalyzer-like) |
| `ShodanCollector` | Recherche Shodan (host, search, counts) |
| `CensysCollector` | Recherche Censys (IPv4, certificates, search) |
| `GraphEngine` | Moteur de graphe d'entités (NetworkX, Maltego-like) |
| `Entity` / `Relation` | Entités et relations pour le graphe |
| `Transform` | Transforms pour expansion automatique du graphe |
| `OsintOrchestrator` | Investigation automatisée multi-sources |
| `OsintMonitor` | Monitoring OSINT continu |

### Partie 2 — Proxy / Web (`decepticon.navmax.proxy`)

| Classe / Fonction | Rôle |
|---|---|
| `ProxyServer` | Proxy HTTP/HTTPS MITM |
| `Interceptor` | Interception pause/modify/forward (Burp-like) |
| `Repeater` | Rejeu de requêtes |
| `WebScanner` | Scanner web (XSS, SQLi, path traversal, headers) |
| `Fuzzer` | Fuzzer paramétrique |
| `Intruder` | Intruder multi-payloads (Burp Intruder-like) |
| `Crawler` | Crawler web |
| `PlaywrightSpider` | Spider basé sur Playwright (JavaScript) |

## Workflow typique

```python
from decepticon.navmax.osint import DnsCollector, WhoisCollector, SslCollector, OsintOrchestrator

# 1. Collecte DNS
dns = DnsCollector()
records = dns.collect("example.com")
for r in records:
    print(r.type, r.value)

# 2. WHOIS
whois = WhoisCollector()
info = whois.lookup("example.com")
print(info.registrar, info.creation_date)

# 3. SSL
ssl = SslCollector()
cert = ssl.collect("example.com", port=443)
print(cert.issuer, cert.san_list)

# 4. Investigation orchestrée
orchestrator = OsintOrchestrator()
report = orchestrator.investigate("example.com")
report.export_json("recon_report.json")

# 5. Graphe d'entités
from decepticon.navmax.osint import GraphEngine, Entity, Relation
g = GraphEngine()
g.add_entity(Entity(name="example.com", type="domain"))
g.add_entity(Entity(name="192.0.2.1", type="ip"))
g.add_relation(Relation("example.com", "resolves_to", "192.0.2.1"))
graph = g.build_graph()

# 6. Proxy MITM + scan
from decepticon.navmax.proxy import ProxyServer, WebScanner
proxy = ProxyServer(host="0.0.0.0", port=8080)
scanner = WebScanner()
vulns = scanner.scan_target("http://192.168.1.100:8080")
```

## Dépendances

- `dnspython` pour collecte DNS
- `python-whois` pour WHOIS
- `cryptography` pour SSL
- `shodan` (optionnel) API Shodan
- `censys` (optionnel) API Censys
- `mitmproxy` (optionnel) pour ProxyServer avancé
- `playwright` (optionnel) pour PlaywrightSpider
