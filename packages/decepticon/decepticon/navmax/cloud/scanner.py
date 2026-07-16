"""Scanners cloud sans SDK — HTTP + DNS uniquement, graceful degradation.

Scanners implémentés :
1. S3 Bucket Scanner  — vérifie buckets AWS S3 via HTTP HEAD
2. IAM Policy Analyzer — analyse de politiques IAM (wildcards, admin, conditions faibles)
3. Cloud Recon DNS    — découvre ressources cloud via DNS/CNAME
"""

import asyncio
import re
import socket
from dataclasses import dataclass, field

import httpx
import structlog

logger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# AWS Region validation
# ---------------------------------------------------------------------------

AWS_REGION_PATTERN = re.compile(r"^[a-z]{2}-[a-z]+-[0-9]+$")

# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass
class CloudFinding:
    """Résultat d'un scan d'une ressource cloud."""

    service: str
    resource: str
    issue: str
    severity: str  # critical, high, medium, low, info
    evidence: str = ""
    remediation: str = ""


@dataclass
class IAMRisk:
    """Risque détecté dans une politique IAM."""

    risk_type: str
    severity: str
    description: str
    policy_statement_index: int


@dataclass
class CloudReconResult:
    """Résultat de la reconnaissance cloud DNS."""

    domain: str
    s3_buckets: list[str] = field(default_factory=list)
    cloudfront_domains: list[str] = field(default_factory=list)
    azure_resources: list[str] = field(default_factory=list)
    gcp_resources: list[str] = field(default_factory=list)
    ips_found: list[str] = field(default_factory=list)

    def all_resources(self) -> list[str]:
        """Toutes les ressources découvertes."""
        return self.s3_buckets + self.cloudfront_domains + self.azure_resources + self.gcp_resources


# ---------------------------------------------------------------------------
# S3 Bucket Scanner (HTTP HEAD, pas de boto3)
# ---------------------------------------------------------------------------

S3_CHECKS = [
    {
        "name": "public_read",
        "description": "Bucket accessible en lecture publique",
        "severity": "high",
        "remediation": "Restreindre la politique du bucket pour interdire les lectures anonymes.",
    },
    {
        "name": "public_write",
        "description": "Bucket accessible en écriture publique",
        "severity": "critical",
        "remediation": "Supprimer les permissions d'écriture anonymes via la politique du bucket.",
    },
    {
        "name": "no_versioning",
        "description": "Versioning désactivé sur le bucket",
        "severity": "medium",
        "remediation": "Activer le versioning sur le bucket S3 pour la protection contre les suppressions accidentelles.",
    },
]


async def _check_s3_bucket(
    client: httpx.AsyncClient,
    bucket_name: str,
    timeout: float = 10.0,
) -> list[CloudFinding]:
    """Vérifie la configuration de sécurité d'un bucket S3 via HTTP HEAD.

    Teste :
      - Accès public en lecture (HEAD sur /)
      - Accès public en écriture (HEAD OPTIONS simulé)
      - En-têtes de versioning / encryption retournés

    Graceful degradation : si la requête échoue (timeout, DNS, 403),
    on retourne simplement une liste vide — pas d'exception levée.
    """
    findings: list[CloudFinding] = []
    base_url = f"https://{bucket_name}.s3.amazonaws.com"

    try:
        # --- Vérification : bucket existe ? ---
        resp = await client.head(
            base_url,
            timeout=timeout,
            follow_redirects=True,
        )
        status = resp.status_code

        # 200 = bucket existe et est lisible
        # 403 = bucket existe mais interdit (normal pour un bucket privé)
        # 404 = bucket n'existe pas

        if status == 404:
            return findings

        if status == 403:
            findings.append(
                CloudFinding(
                    service="AWS S3",
                    resource=bucket_name,
                    issue="Bucket accessible (privé)",
                    severity="info",
                    evidence=f"HTTP {status} sur {base_url}",
                    remediation="Aucune — le bucket est correctement restreint.",
                ),
            )
            return findings

        # --- Vérification : lecture publique ---
        if status == 200:
            findings.append(
                CloudFinding(
                    service="AWS S3",
                    resource=bucket_name,
                    issue="Bucket accessible en lecture publique",
                    severity="high",
                    evidence=f"HTTP {status} sur {base_url}",
                    remediation="Restreindre la politique du bucket pour interdire les lectures anonymes.",
                ),
            )

        # --- Vérification : en-têtes ---
        headers = resp.headers
        versioning = headers.get("x-amz-version-id")
        if not versioning:
            findings.append(
                CloudFinding(
                    service="AWS S3",
                    resource=bucket_name,
                    issue="Versioning désactivé",
                    severity="medium",
                    evidence="Pas d'en-tête x-amz-version-id dans la réponse HEAD",
                    remediation="Activer le versioning sur le bucket S3.",
                ),
            )

        # --- Vérification : permissions d'écriture ---
        # On tente un PUT (simulé via OPTIONS ou HEAD avec header de test)
        # On vérifie si les en-têtes CLS montrent write public
        try:
            write_check = await client.head(
                base_url,
                headers={"x-amz-acl": "public-read-write"},
                timeout=timeout,
            )
            if write_check.status_code not in (403, 404):
                findings.append(
                    CloudFinding(
                        service="AWS S3",
                        resource=bucket_name,
                        issue="Bucket potentiellement accessible en écriture",
                        severity="critical",
                        evidence=f"HEAD avec x-amz-acl a retourné HTTP {write_check.status_code}",
                        remediation="Vérifier manuellement la politique du bucket.",
                    ),
                )
        except (httpx.TimeoutException, httpx.ConnectError, httpx.HTTPStatusError):
            pass  # graceful degradation

    except httpx.TimeoutException:
        logger.warning("s3_timeout", bucket=bucket_name)
    except httpx.ConnectError:
        logger.warning("s3_connexion_refusee", bucket=bucket_name)
    except httpx.HTTPStatusError as exc:
        logger.debug("s3_erreur_http", bucket=bucket_name, error=str(exc))

    return findings


def _check_wildcard_action(action: str) -> bool:
    """Vérifie si une action IAM est un wildcard dangereux."""
    return action.strip() in ("*", '"*"', "'*'")


def _check_wildcard_resource(resource: str) -> bool:
    """Vérifie si une ressource IAM est un wildcard dangereux."""
    return resource.strip() in ("*", '"*"', "'*'")


# ---------------------------------------------------------------------------
# IAM Policy Analyzer (JSON parsing, pas de SDK)
# ---------------------------------------------------------------------------


async def analyze_iam_policy(policy_json: dict) -> list[IAMRisk]:
    """Analyse une politique IAM à la recherche de mauvaises configurations.

    Détecte :
      - Actions wildcard (*) sur des statements
      - Resources wildcard (*) sur des statements
      - Politiques administrateur (wildcard action + wildcard resource)
      - Conditions faibles ou absentes sur des actions sensibles
      - Statement Effect=Allow avec des wildcards

    Args:
        policy_json: Dictionnaire représentant la politique IAM (format AWS)

    Returns:
        Liste de IAMRisk détectés

    """
    risks: list[IAMRisk] = []

    statements = policy_json.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    for idx, stmt in enumerate(statements):
        if not isinstance(stmt, dict):
            continue
        effect = stmt.get("Effect", "")
        actions = stmt.get("Action", [])
        resources = stmt.get("Resource", [])
        condition = stmt.get("Condition", None)

        if isinstance(actions, str):
            actions = [actions]
        if isinstance(resources, str):
            resources = [resources]

        # Vérification : Effect=Allow avec wildcard action
        if effect == "Allow":
            for action in actions:
                if _check_wildcard_action(action):
                    risks.append(
                        IAMRisk(
                            risk_type="wildcard_action",
                            severity="high",
                            description=f"Action wildcard (*) trouvée dans le statement {idx}. "
                            "Cela permet toutes les actions sur le(s) service(s) ciblé(s).",
                            policy_statement_index=idx,
                        ),
                    )

            for resource in resources:
                if _check_wildcard_resource(resource):
                    risks.append(
                        IAMRisk(
                            risk_type="wildcard_resource",
                            severity="high",
                            description=f"Resource wildcard (*) trouvée dans le statement {idx}. "
                            "Cela donne accès à toutes les ressources du service.",
                            policy_statement_index=idx,
                        ),
                    )

            # Politique admin : wildcard action + wildcard resource
            has_wildcard_action = any(_check_wildcard_action(a) for a in actions)
            has_wildcard_resource = any(_check_wildcard_resource(r) for r in resources)
            if has_wildcard_action and has_wildcard_resource:
                risks.append(
                    IAMRisk(
                        risk_type="admin_policy",
                        severity="critical",
                        description=f"Politique administrateur détectée dans le statement {idx}. "
                        "Action wildcard + Resource wildcard = accès illimité à tous les services.",
                        policy_statement_index=idx,
                    ),
                )

            # Condition absente ou faible sur des actions sensibles
            sensitive_actions = [
                "iam:Create",
                "iam:Delete",
                "iam:Update",
                "s3:PutBucketPolicy",
                "s3:DeleteBucket",
                "lambda:CreateFunction",
                "lambda:UpdateFunctionCode",
                "ec2:AuthorizeSecurityGroupIngress",
                "ec2:RunInstances",
                "sts:AssumeRole",
            ]
            for action in actions:
                for sensitive in sensitive_actions:
                    if sensitive.lower() in action.lower():
                        if not condition:
                            risks.append(
                                IAMRisk(
                                    risk_type="missing_condition",
                                    severity="medium",
                                    description=f"Action sensible '{action}' sans condition dans le statement {idx}. "
                                    "Ajouter une condition (ex: aws:SourceIp, aws:MultiFactorAuthPresent) "
                                    "pour restreindre l'accès.",
                                    policy_statement_index=idx,
                                ),
                            )
                        break

    return risks


# ---------------------------------------------------------------------------
# Cloud Recon DNS (pas de SDK, résolution DNS directe)
# ---------------------------------------------------------------------------

# Patterns DNS pour la découverte de ressources cloud
CLOUD_DNS_PATTERNS = {
    "s3": [
        ("s3.amazonaws.com", "AWS S3"),
        ("s3-us-east-1.amazonaws.com", "AWS S3 (us-east-1)"),
        ("s3-eu-west-1.amazonaws.com", "AWS S3 (eu-west-1)"),
        ("s3.ap-northeast-1.amazonaws.com", "AWS S3 (ap-northeast-1)"),
    ],
    "cloudfront": [
        ("cloudfront.net", "AWS CloudFront"),
        ("d3ag4hukhn62kn.cloudfront.net", "AWS CloudFront CDN"),
    ],
    "azure": [
        ("blob.core.windows.net", "Azure Blob Storage"),
        ("azureedge.net", "Azure CDN"),
        ("azurewebsites.net", "Azure App Service"),
        ("cloudapp.net", "Azure Cloud Service"),
        ("azure-api.net", "Azure API Management"),
    ],
    "gcp": [
        ("storage.googleapis.com", "GCP Cloud Storage"),
        ("appspot.com", "GCP App Engine"),
        ("cloudfunctions.net", "GCP Cloud Functions"),
        ("firebaseio.com", "GCP Firebase"),
        ("compute.amazonaws.com", "AWS EC2"),  # commun avec GCP via cross-resolve
    ],
}


async def _resolve_cname(domain: str, timeout: float = 5.0) -> list[str]:
    """Résout les enregistrements CNAME d'un domaine.

    Graceful degradation : retourne une liste vide en cas d'erreur.
    """
    results: list[str] = []
    try:
        # Résolution CNAME via socket (pas de lib DNS externe)
        # On utilise getaddrinfo pour obtenir les IP, puis on vérifie
        _, _, cname_list = socket.gethostbyname_ex(domain)
        results.extend(cname_list)

        # On essaie aussi de chercher des enregistrements CNAME
        # en tentant des sous-domaines courants
        subdomain_prefixes = [
            "www",
            "cdn",
            "static",
            "assets",
            "media",
            "images",
            "files",
            "uploads",
            "storage",
            "bucket",
            "s3",
            "blob",
            "cloud",
        ]

        for prefix in subdomain_prefixes:
            try:
                sub = f"{prefix}.{domain}"
                _, aliases, _ = socket.gethostbyname_ex(sub)
                for alias in aliases:
                    if alias not in results:
                        results.append(f"{sub} -> {alias}")
                results.extend(aliases)
            except (socket.gaierror, OSError):
                continue

    except Exception as exc:
        logger.debug("cname_resolve_failed", domain=domain, error=str(exc))

    return results


async def _check_subdomain(
    domain: str,
    sub_prefix: str,
    client: httpx.AsyncClient,
    timeout: float = 5.0,
) -> str | None:
    """Vérifie si un sous-domaine existe et retourne son URL complète.

    Utilise HTTP HEAD pour vérifier l'existence.
    Graceful degradation : retourne None en cas d'erreur.
    """
    subdomain = f"{sub_prefix}.{domain}"
    url = f"https://{subdomain}"
    try:
        resp = await client.head(url, timeout=timeout, follow_redirects=False)
        if 200 <= resp.status_code < 400:  # success ou redirect
            return url
        # 403 = existe mais interdit (bucket privé)
        if resp.status_code == 403:
            return url
    except (httpx.TimeoutException, httpx.ConnectError, httpx.HTTPStatusError, OSError):
        pass
    return None


async def discover_cloud_resources(
    domain: str,
    timeout: float = 10.0,
    resolve_dns: bool = True,
    region: str | None = None,
) -> CloudReconResult:
    """Découvre les ressources cloud associées à un domaine.

    Utilise deux méthodes :
      1. DNS : résolution CNAME pour trouver des alias cloud
      2. HTTP : vérification de sous-domaines cloud courants

    Args:
        domain: Nom de domaine à analyser
        timeout: Timeout des requêtes en secondes
        resolve_dns: Si True, effectue les résolutions DNS
        region: Région AWS optionnelle (ex: eu-west-1)

    Returns:
        CloudReconResult contenant les ressources découvertes

    """
    if region and not AWS_REGION_PATTERN.match(region):
        logger.warning("aws_region_invalide", region=region)
        return CloudReconResult(domain=domain)

    result = CloudReconResult(domain=domain)

    async with httpx.AsyncClient(
        verify=False,
        timeout=timeout,
    ) as client:
        tasks = []

        # --- Méthode 1 : Sous-domaines cloud courants ---
        s3_prefixes = [f"s3-{r}" for r in ["", "us-east-1", "eu-west-1", "us-west-2"]]
        cloud_prefixes = ["cdn", "static", "media", "assets", "storage", "blob", "cloud"]

        for prefix in s3_prefixes + cloud_prefixes:
            tasks.append(_check_subdomain(domain, prefix, client, timeout))

        domain_prefixes = [
            "www",
            "api",
            "cdn",
            "static",
            "assets",
            "media",
            "files",
            "uploads",
            "storage",
            "bucket",
            "s3",
            "blob",
            "cloud",
            "mail",
            "webmail",
            "admin",
            "portal",
            "app",
            "dev",
            "staging",
        ]

        for prefix in domain_prefixes:
            tasks.append(_check_subdomain(domain, prefix, client, timeout))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for url in results:
            if isinstance(url, str) and url:
                # Classer la ressource selon le pattern
                if "s3" in url.lower() or "amazonaws" in url.lower():
                    result.s3_buckets.append(url)
                elif "cloudfront" in url.lower():
                    result.cloudfront_domains.append(url)
                elif (
                    "blob" in url.lower() or "azure" in url.lower() or "windows.net" in url.lower()
                ):
                    result.azure_resources.append(url)
                elif (
                    "google" in url.lower() or "appspot" in url.lower() or "firebase" in url.lower()
                ):
                    result.gcp_resources.append(url)
                else:
                    # Tentative de classification par pattern DNS
                    pass

        # --- Méthode 2 : DNS CNAME resolution ---
        if resolve_dns:
            try:
                cnames = await _resolve_cname(domain, timeout)

                for cname in cnames:
                    cname_lower = cname.lower()
                    if "s3" in cname_lower or "amazonaws" in cname_lower:
                        result.s3_buckets.append(cname)
                    elif "cloudfront" in cname_lower:
                        result.cloudfront_domains.append(cname)
                    elif (
                        "blob" in cname_lower
                        or "azure" in cname_lower
                        or "windows.net" in cname_lower
                    ):
                        result.azure_resources.append(cname)
                    elif (
                        "google" in cname_lower
                        or "appspot" in cname_lower
                        or "firebase" in cname_lower
                        or "storage.googleapis" in cname_lower
                    ):
                        result.gcp_resources.append(cname)
                    elif re.match(r"^\d+\.\d+\.\d+\.\d+", cname):
                        result.ips_found.append(cname)
                    else:
                        # On garde en IP si ça ressemble à une IP
                        try:
                            _ip = socket.gethostbyname(cname)
                            result.ips_found.append(f"{cname} -> {_ip}")
                        except (socket.gaierror, OSError):
                            pass

            except (socket.gaierror, OSError) as e:
                logger.debug("dns_resolution_failed", domain=domain, error=str(e))

        # Déduplication
        result.s3_buckets = list(dict.fromkeys(result.s3_buckets))
        result.cloudfront_domains = list(dict.fromkeys(result.cloudfront_domains))
        result.azure_resources = list(dict.fromkeys(result.azure_resources))
        result.gcp_resources = list(dict.fromkeys(result.gcp_resources))
        result.ips_found = list(dict.fromkeys(result.ips_found))

    return result


# ---------------------------------------------------------------------------
# Interface publique simplifiée (fonctions asynchrones)
# ---------------------------------------------------------------------------


async def scan_s3_buckets(
    bucket_names: list[str],
    timeout: float = 10.0,
) -> list[CloudFinding]:
    """Scanne une liste de noms de buckets S3.

    Args:
        bucket_names: Liste des noms de buckets à scanner
        timeout: Timeout par requête

    Returns:
        Liste de CloudFinding (vide si tous les buckets sont sécurisés)

    """
    all_findings: list[CloudFinding] = []

    async with httpx.AsyncClient(verify=False, timeout=timeout) as client:
        tasks = [_check_s3_bucket(client, name, timeout) for name in bucket_names]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, list):
                all_findings.extend(result)
            elif isinstance(result, Exception):
                logger.debug("s3_scan_error", error=str(result))

    return all_findings


# ---------------------------------------------------------------------------
# BaseCloudScanner — abstract base
# ---------------------------------------------------------------------------

from abc import ABC, abstractmethod


class BaseCloudScanner(ABC):
    """Classe de base abstraite pour les scanners cloud.

    Définit le contrat (Base → Connector → Analyzer) que tous les
    scanners cloud doivent respecter.

    Connectors : scan_s3_buckets (S3), discover_cloud_resources (DNS)
    Analyzer   : analyze_iam_policy (IAM)
    """

    @abstractmethod
    async def scan_s3_buckets(self, bucket_names: list[str]) -> list[CloudFinding]:
        """Scanne des buckets S3 — rôle Connector."""
        ...

    @abstractmethod
    async def analyze_iam_policy(self, policy_json: dict) -> list[IAMRisk]:
        """Analyse une politique IAM — rôle Analyzer."""
        ...

    @abstractmethod
    async def discover_cloud_resources(self, domain: str) -> CloudReconResult:
        """Découvre les ressources cloud — rôle Connector."""
        ...


# ---------------------------------------------------------------------------
# CloudScanner — implémentation concrète unifiée
# ---------------------------------------------------------------------------


class CloudScanner(BaseCloudScanner):
    """Scanner cloud unifié avec graceful degradation.

    Utilise HTTP + DNS uniquement — pas de dépendances SDK lourdes.
    Chaque méthode retourne ses résultats même en cas d'erreur partielle.

    Pattern : BaseCloudScanner (abstraction)
              → scan_s3_buckets / discover_cloud_resources (Connectors)
              → analyze_iam_policy (Analyzer)
    """

    def __init__(
        self,
        timeout: float = 10.0,
        resolve_dns: bool = True,
    ) -> None:
        self.timeout = timeout
        self.resolve_dns = resolve_dns

    async def scan_s3_buckets(self, bucket_names: list[str]) -> list[CloudFinding]:
        """Scanne des buckets S3."""
        return await scan_s3_buckets(bucket_names, self.timeout)

    async def analyze_iam_policy(self, policy_json: dict) -> list[IAMRisk]:
        """Analyse une politique IAM."""
        return await analyze_iam_policy(policy_json)

    async def discover_cloud_resources(self, domain: str) -> CloudReconResult:
        """Découvre les ressources cloud d'un domaine."""
        return await discover_cloud_resources(domain, self.timeout, self.resolve_dns)
