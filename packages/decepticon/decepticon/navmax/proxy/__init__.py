"""Module Proxy — interception web (Burp Suite-like).

Fonctionnalités :
- Proxy HTTP/HTTPS MITM avec certificats auto-générés
- Interception : pause/modify/forward
- Repeater : rejouer des requêtes
- Scanner web : XSS, SQLi, path traversal, headers
- Fuzzer : injection paramétrique
"""

from .fuzzer import Fuzzer, FuzzReport, FuzzResult
from .interceptor import FlowAction, FlowStatus, InterceptedFlow, Interceptor
from .intruder import (
    PREDEFINED_PAYLOADS,
    Intruder,
    IntruderFilters,
    IntruderReport,
    IntruderResult,
    quick_attack,
)
from .proxy_server import ProxyServer
from .repeater import Repeater, RepeaterRequest, RepeaterResponse
from .scanner import Vulnerability, WebScanner

__all__ = [
    "PREDEFINED_PAYLOADS",
    "FlowAction",
    "FlowStatus",
    "FuzzReport",
    "FuzzResult",
    "Fuzzer",
    "InterceptedFlow",
    "Interceptor",
    "Intruder",
    "IntruderFilters",
    "IntruderReport",
    "IntruderResult",
    "ProxyServer",
    "Repeater",
    "RepeaterRequest",
    "RepeaterResponse",
    "Vulnerability",
    "WebScanner",
    "quick_attack",
]
