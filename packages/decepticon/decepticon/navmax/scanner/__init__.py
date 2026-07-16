"""Module Scanner — reconnaissance réseau (Nmap-like).

Fonctionnalités :
- TCP Connect Scan (sans privilèges admin)
- UDP Scan (nécessite admin)
- Détection de services (banner grabbing)
- Fingerprinting OS (TTL, flags TCP)
"""

from .engine import parse_ports, run_scan, run_scan_background
from .fingerprint import detect_os, detect_service
from .nuclei_scanner import NucleiFinding, NucleiNotFoundError, NucleiScanner, NucleiTimeoutError
from .tcp import tcp_connect_scan

__all__ = [
    "NucleiFinding",
    "NucleiNotFoundError",
    "NucleiScanner",
    "NucleiTimeoutError",
    "detect_os",
    "detect_service",
    "parse_ports",
    "run_scan",
    "run_scan_background",
    "tcp_connect_scan",
]
