"""Transformations — règles à la Maltego.

Une transformation prend une entité en entrée et produit de nouvelles entités
et relations. C'est le cœur de l'expansion automatique du graphe OSINT.
"""

from decepticon.navmax.core.logging import get_logger

from .engine import GraphEngine
from .entities import Entity, EntityType, RelationType

logger = get_logger(__name__)


class Transform:
    """Transformation OSINT — une règle qui étend le graphe.

    Chaque transform a :
    - input_type : type d'entité d'entrée
    - name : nom lisible
    - description : ce que fait la transformation
    - run() : exécute la transformation
    """

    def __init__(
        self,
        name: str,
        input_type: EntityType,
        description: str = "",
    ) -> None:
        self.name = name
        self.input_type = input_type
        self.description = description

    async def run(self, entity: Entity, graph: GraphEngine) -> list[Entity]:
        """Exécute la transformation. À surcharger."""
        return []


# ---------------------------------------------------------------------------
# Transforms intégrées
# ---------------------------------------------------------------------------
class DomainToDns(Transform):
    """Domaine → enregistrements DNS."""

    def __init__(self) -> None:
        super().__init__(
            "Domain → DNS", EntityType.DOMAIN, "Résout les enregistrements DNS d'un domaine",
        )

    async def run(self, entity: Entity, graph: GraphEngine) -> list[Entity]:
        from decepticon.navmax.osint.collectors.dns import DnsCollector

        domain = entity.value
        records = await DnsCollector.lookup(domain)

        new_entities: list[Entity] = []
        record_type_to_relation: dict[str, RelationType] = {
            "A": RelationType.A_RECORD,
            "AAAA": RelationType.AAAA_RECORD,
            "MX": RelationType.MX_RECORD,
            "NS": RelationType.NS_RECORD,
            "CNAME": RelationType.CNAME_RECORD,
            "TXT": RelationType.TXT_RECORD,
            "SOA": RelationType.SOA_RECORD,
        }

        for rec in records:
            if rec.type == "MX":
                # Serveur MX → nouvelle entité domaine
                mx_entity = Entity(
                    type=EntityType.DOMAIN,
                    value=rec.value,
                    label=f"MX: {rec.value}",
                    properties={"priority": rec.priority},
                    sources=["DNS"],
                )
                graph.add_relation(entity, mx_entity, RelationType.MX_RECORD)
                new_entities.append(mx_entity)

            elif rec.type in {"A", "AAAA"}:
                ip_entity = Entity(
                    type=EntityType.IP,
                    value=rec.value,
                    label=rec.value,
                    sources=["DNS"],
                )
                rel_type = record_type_to_relation.get(rec.type, RelationType.RELATED_TO)
                graph.add_relation(entity, ip_entity, rel_type)
                new_entities.append(ip_entity)

            elif rec.type == "NS":
                ns_entity = Entity(
                    type=EntityType.NAME_SERVER,
                    value=rec.value,
                    label=f"NS: {rec.value}",
                    sources=["DNS"],
                )
                graph.add_relation(entity, ns_entity, RelationType.NS_RECORD)
                new_entities.append(ns_entity)

            elif rec.type == "CNAME":
                cname_entity = Entity(
                    type=EntityType.DOMAIN,
                    value=rec.value,
                    label=rec.value,
                    sources=["DNS"],
                )
                graph.add_relation(entity, cname_entity, RelationType.CNAME_RECORD)
                new_entities.append(cname_entity)

        logger.info("transform_dns", domain=domain, records=len(records), new=len(new_entities))
        return new_entities


class DomainToWhois(Transform):
    """Domaine → WHOIS."""

    def __init__(self) -> None:
        super().__init__(
            "Domain → WHOIS", EntityType.DOMAIN, "Récupère les infos WHOIS d'un domaine",
        )

    async def run(self, entity: Entity, graph: GraphEngine) -> list[Entity]:
        from decepticon.navmax.osint.collectors.whois import WhoisCollector

        domain = entity.value
        info = await WhoisCollector.lookup(domain)
        new_entities: list[Entity] = []

        if not info:
            return new_entities

        # Registrar
        if info.registrar:
            reg_entity = Entity(
                type=EntityType.ORGANIZATION,
                value=info.registrar,
                label=info.registrar,
                sources=["WHOIS"],
            )
            graph.add_relation(entity, reg_entity, RelationType.WHOIS_REGISTRAR)
            new_entities.append(reg_entity)

        # Registrant
        if info.registrant_name:
            person = Entity(
                type=EntityType.PERSON,
                value=info.registrant_name,
                label=info.registrant_name,
                properties={"org": info.registrant_org} if info.registrant_org else {},
                sources=["WHOIS"],
            )
            graph.add_relation(entity, person, RelationType.WHOIS_REGISTRANT)
            new_entities.append(person)

        # Organization
        if info.registrant_org and info.registrant_org != info.registrar:
            org = Entity(
                type=EntityType.ORGANIZATION,
                value=info.registrant_org,
                label=info.registrant_org,
                sources=["WHOIS"],
            )
            graph.add_relation(entity, org, RelationType.WHOIS_REGISTRANT)
            new_entities.append(org)

        # Email registrant
        if info.registrant_email:
            email = Entity(
                type=EntityType.EMAIL,
                value=info.registrant_email,
                label=info.registrant_email,
                sources=["WHOIS"],
            )
            graph.add_relation(entity, email, RelationType.HAS_CONTACT)
            new_entities.append(email)

        # Name servers
        for ns in info.name_servers:
            ns_entity = Entity(
                type=EntityType.NAME_SERVER,
                value=ns,
                label=f"NS: {ns}",
                sources=["WHOIS"],
            )
            graph.add_relation(entity, ns_entity, RelationType.NS_RECORD)
            new_entities.append(ns_entity)

        # Dates clés → propriétés
        entity.properties["creation_date"] = info.creation_date or ""
        entity.properties["expiration_date"] = info.expiration_date or ""

        logger.info("transform_whois", domain=domain, new=len(new_entities))
        return new_entities


class IpToSSL(Transform):
    """IP → Certificat SSL."""

    def __init__(self) -> None:
        super().__init__("IP → SSL", EntityType.IP, "Récupère le certificat SSL d'une IP")

    async def run(self, entity: Entity, graph: GraphEngine) -> list[Entity]:
        from decepticon.navmax.osint.collectors.ssl import SslCollector

        ip = entity.value
        info = await SslCollector.get_cert(ip)
        new_entities: list[Entity] = []

        if not info or not info.subject:
            return new_entities

        # Certificat
        cert_entity = Entity(
            type=EntityType.SSL_CERT,
            value=info.fingerprint_sha256 or info.serial_number,
            label=f"SSL: {info.subject[:60]}",
            properties={
                "subject": info.subject,
                "issuer": info.issuer,
                "not_before": info.not_before,
                "not_after": info.not_after,
                "days_remaining": info.days_remaining,
                "is_valid": info.is_valid,
            },
            sources=["SSL"],
        )
        graph.add_relation(entity, cert_entity, RelationType.SSL_FOR_HOST)
        new_entities.append(cert_entity)

        # Issuer
        if info.issuer:
            issuer_entity = Entity(
                type=EntityType.ORGANIZATION,
                value=info.issuer,
                label=f"CA: {info.issuer[:60]}",
                sources=["SSL"],
            )
            graph.add_relation(cert_entity, issuer_entity, RelationType.SSL_ISSUED_BY)
            new_entities.append(issuer_entity)

        # SANs
        for san in info.san:
            # Déterminer si c'est un domaine ou une IP
            import re

            if re.match(r"^\d+\.\d+\.\d+\.\d+$", san):
                san_type = EntityType.IP
            else:
                san_type = EntityType.DOMAIN

            san_entity = Entity(
                type=san_type,
                value=san,
                label=san,
                sources=["SSL/SAN"],
            )
            graph.add_relation(cert_entity, san_entity, RelationType.SSL_SAN)
            new_entities.append(san_entity)

        logger.info("transform_ssl", ip=ip, sans=len(info.san))
        return new_entities


class DomainToWeb(Transform):
    """Domaine → Analyse web (technos, emails, liens)."""

    def __init__(self) -> None:
        super().__init__(
            "Domain → Web", EntityType.DOMAIN, "Analyse la page web : technos, emails, liens",
        )

    async def run(self, entity: Entity, graph: GraphEngine) -> list[Entity]:
        from decepticon.navmax.osint.collectors.web import WebCollector

        domain = entity.value
        collector = WebCollector()
        info = await collector.analyze(domain)
        await collector.close()

        new_entities: list[Entity] = []

        if not info:
            return new_entities

        # Technologies
        for tech in info.technologies:
            tech_entity = Entity(
                type=EntityType.TECHNOLOGY,
                value=tech,
                label=tech,
                sources=["Web/Tech"],
            )
            graph.add_relation(entity, tech_entity, RelationType.RUNS)
            new_entities.append(tech_entity)

        # Emails
        for email in info.emails_found:
            email_entity = Entity(
                type=EntityType.EMAIL,
                value=email,
                label=email,
                sources=["Web/Email"],
            )
            graph.add_relation(entity, email_entity, RelationType.HAS_CONTACT)
            new_entities.append(email_entity)

        # Liens externes → domaines
        seen_domains: set[str] = set()
        from urllib.parse import urlparse

        for link in info.links_external[:20]:
            try:
                parsed = urlparse(link)
                link_domain = parsed.netloc.lower()
                if link_domain and link_domain not in seen_domains:
                    seen_domains.add(link_domain)
                    link_entity = Entity(
                        type=EntityType.DOMAIN,
                        value=link_domain,
                        label=link_domain,
                        sources=["Web/Link"],
                    )
                    graph.add_relation(entity, link_entity, RelationType.LINKED_TO)
                    new_entities.append(link_entity)
            except ValueError:
                pass

        # Social links
        for platform, url in info.social_links.items():
            soc = Entity(
                type=EntityType.SOCIAL_ACCOUNT,
                value=f"{platform}:{url}",
                label=f"{platform}: {url}",
                properties={"platform": platform},
                sources=["Web/Social"],
            )
            graph.add_relation(entity, soc, RelationType.LINKED_TO)
            new_entities.append(soc)

        logger.info("transform_web", domain=domain, new=len(new_entities))
        return new_entities


class IpToReverseDns(Transform):
    """IP → Reverse DNS."""

    def __init__(self) -> None:
        super().__init__("IP → Reverse DNS", EntityType.IP, "Reverse DNS lookup")

    async def run(self, entity: Entity, graph: GraphEngine) -> list[Entity]:
        from decepticon.navmax.osint.collectors.dns import DnsCollector

        ip = entity.value
        records = await DnsCollector.reverse_lookup(ip)
        new_entities: list[Entity] = []

        for rec in records:
            domain_entity = Entity(
                type=EntityType.DOMAIN,
                value=rec.value,
                label=rec.value,
                sources=["DNS/PTR"],
            )
            graph.add_relation(entity, domain_entity, RelationType.PTR_RECORD)
            new_entities.append(domain_entity)

        return new_entities


# ---------------------------------------------------------------------------
# Registre des transforms
# ---------------------------------------------------------------------------
ALL_TRANSFORMS: dict[tuple[EntityType, str], Transform] = {}


def register_transform(transform: Transform) -> None:
    ALL_TRANSFORMS[(transform.input_type, transform.name)] = transform


for t_cls in [DomainToDns, DomainToWhois, IpToSSL, DomainToWeb, IpToReverseDns]:
    register_transform(t_cls())


def get_transforms_for(entity_type: EntityType) -> list[Transform]:
    """Retourne toutes les transformations applicables à un type d'entité."""
    return [t for (et, _), t in ALL_TRANSFORMS.items() if et == entity_type]
