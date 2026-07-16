"""Collecteurs OSINT NavMAX."""

from .censys import CensysCollector, CensysResult
from .dns import DnsCollector, DnsRecord
from .shodan import CrtShCollector, CrtShResult, ShodanCollector, ShodanResult
from .ssl import SslCertInfo, SslCollector
from .web import WebCollector, WebTechInfo
from .whois import WhoisCollector, WhoisInfo

__all__ = [
    "CensysCollector",
    "CensysResult",
    "CrtShCollector",
    "CrtShResult",
    "DnsCollector",
    "DnsRecord",
    "ShodanCollector",
    "ShodanResult",
    "SslCertInfo",
    "SslCollector",
    "WebCollector",
    "WebTechInfo",
    "WhoisCollector",
    "WhoisInfo",
]
