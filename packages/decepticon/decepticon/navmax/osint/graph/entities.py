"""Types d'entités du graphe OSINT NavMAX."""

import uuid
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class EntityType(StrEnum):
    DOMAIN = "domain"
    IP = "ip"
    SUBNET = "subnet"
    PERSON = "person"
    EMAIL = "email"
    ORGANIZATION = "organization"
    URL = "url"
    SSL_CERT = "ssl_cert"
    DNS_RECORD = "dns_record"
    NAME_SERVER = "name_server"
    TECHNOLOGY = "technology"
    SOCIAL_ACCOUNT = "social_account"
    PHONE = "phone"
    LOCATION = "location"
    HASH = "hash"
    FILE = "file"
    CVE = "cve"
    UNKNOWN = "unknown"


class RelationType(StrEnum):
    A_RECORD = "a_record"
    AAAA_RECORD = "aaaa_record"
    MX_RECORD = "mx_record"
    NS_RECORD = "ns_record"
    CNAME_RECORD = "cname_record"
    TXT_RECORD = "txt_record"
    SOA_RECORD = "soa_record"
    PTR_RECORD = "ptr_record"
    PARENT_DOMAIN = "parent_domain"
    SUBDOMAIN = "subdomain"
    WHOIS_REGISTRANT = "whois_registrant"
    WHOIS_REGISTRAR = "whois_registrar"
    WHOIS_ADMIN = "whois_admin"
    WHOIS_TECH = "whois_tech"
    SSL_ISSUED_BY = "ssl_issued_by"
    SSL_FOR_HOST = "ssl_for_host"
    SSL_SAN = "ssl_san"
    HOSTS = "hosts"  # Domaine hébergé sur IP
    RUNS = "runs"  # Technologie utilisée
    LINKED_TO = "linked_to"  # Lien web
    EMAIL_BELONGS_TO = "email_belongs_to"
    MEMBER_OF = "member_of"
    LOCATED_AT = "located_at"
    HAS_CONTACT = "has_contact"
    RELATED_TO = "related_to"
    REFERENCES = "references"


@dataclass
class Entity:
    """Nœud du graphe."""

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    type: EntityType = EntityType.UNKNOWN
    value: str = ""
    label: str = ""
    properties: dict[str, Any] = field(default_factory=dict)
    sources: list[str] = field(default_factory=list)  # Sources d'où vient cette info

    def __hash__(self) -> int:
        return hash(self.id)


@dataclass
class Relation:
    """Arête du graphe."""

    source: Entity
    target: Entity
    type: RelationType
    properties: dict[str, Any] = field(default_factory=dict)
    confidence: float = 1.0  # 0.0 → 1.0

    def __repr__(self) -> str:
        return f"{self.source.value} --[{self.type.value}]--> {self.target.value}"
