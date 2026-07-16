"""Scanner de vulnérabilités web — détection automatisée.

Vulnérabilités détectées :
- XSS reflété
- SQLi (error-based, time-based blind)
- Path traversal
- Open redirect
- Headers de sécurité manquants
- Information disclosure
"""

import re
import time
from dataclasses import dataclass
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import httpx

from decepticon.navmax.core.logging import get_logger

logger = get_logger(__name__)


@dataclass
class Vulnerability:
    """Une vulnérabilité web détectée."""

    name: str
    severity: str  # info | low | medium | high | critical
    url: str
    parameter: str | None = None
    payload: str | None = None
    evidence: str | None = None
    description: str = ""
    remediation: str = ""
    cwe: str = ""


# ---------------------------------------------------------------------------
# Payloads de test
# ---------------------------------------------------------------------------
XSS_PAYLOADS = [
    '<script>alert("NavMAX_XSS")</script>',
    '"><script>alert("NavMAX_XSS")</script>',
    '<img src=x onerror=alert("NavMAX_XSS")>',
    '" onmouseover="alert(\'NavMAX_XSS\')"',
    "' onfocus=\"alert('NavMAX_XSS')\" autofocus",
    'javascript:alert("NavMAX_XSS")',
]

SQLI_ERROR_PAYLOADS = [
    "'",
    "''",
    "' OR '1'='1",
    '" OR "1"="1',
    "' OR 1=1--",
    "') OR ('1'='1",
    "1' AND 1=1--",
    "1' AND 1=0--",
    "1 ORDER BY 100--",
]

SQLI_TIME_PAYLOADS = [
    "' OR SLEEP(2)--",
    "1' WAITFOR DELAY '00:00:02'--",
    "'; SELECT pg_sleep(2)--",
    "1' AND (SELECT * FROM (SELECT(SLEEP(2)))a)--",
    "1' OR BENCHMARK(1000000,MD5('a'))--",
]

PATH_TRAVERSAL_PAYLOADS = [
    "../../../etc/passwd",
    "..\\..\\..\\windows\\win.ini",
    "/etc/passwd",
    "C:\\Windows\\System32\\drivers\\etc\\hosts",
    "....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd",
]

OPEN_REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "https:evil.com",
    "%2F%2Fevil.com",
]

SQLI_ERROR_PATTERNS = [
    r"SQL syntax.*?MySQL",
    r"mysql_fetch",
    r"ORA-[0-9]{5}",
    r"PostgreSQL.*?ERROR",
    r"SQLite.*?error",
    r"unclosed quotation mark",
    r"Microsoft OLE DB",
    r"ODBC Driver",
    r"SQL command not properly ended",
    r"Unknown column",
    r"has occurred in the vicinity of",
    r"Incorrect syntax near",
    r"Unclosed quotation mark after",
]

PATH_TRAVERSAL_PATTERNS = [
    r"root:.*:0:",
    r"\[extensions\]",
    r"boot loader",
    r"daemon",
    r"mail|news|uucp",
    r"\[fonts\]",
]

SECURITY_HEADERS = {
    "Strict-Transport-Security": ("medium", "HSTS manquant — risque de downgrade HTTPS"),
    "Content-Security-Policy": (
        "medium",
        "CSP manquant — pas de restriction sur les sources de contenu",
    ),
    "X-Content-Type-Options": ("low", "X-Content-Type-Options manquant — risque de MIME sniffing"),
    "X-Frame-Options": ("medium", "X-Frame-Options manquant — risque de clickjacking"),
    "X-XSS-Protection": ("low", "X-XSS-Protection manquant"),
    "Referrer-Policy": ("low", "Referrer-Policy manquant — fuite d'informations dans le referrer"),
}

INFO_DISCLOSURE_PATTERNS = [
    (
        r"(?:X-AspNet-Version|X-Powered-By|Server):\s*(.+)",
        "low",
        "En-tête {header} exposé : {value}",
    ),
    (r"<!--.*?TODO.*?-->", "low", "Commentaire TODO exposé"),
    (
        r"(?:password|passwd|pwd|secret|api[_-]?key|token)\s*[:=]\s*[\"']?[\w-]+[\"']?",
        "high",
        "Possible credentials dans la réponse",
    ),
    (r"<!--.*?FIXME.*?-->", "low", "Commentaire FIXME exposé"),
]


class WebScanner:
    """Scanner de vulnérabilités web automatisé."""

    def __init__(self, timeout: float = 10.0) -> None:
        self.timeout = timeout
        self._client: httpx.AsyncClient | None = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                verify=False,
                timeout=httpx.Timeout(self.timeout),
                follow_redirects=False,
                headers={"User-Agent": "NavMAX-WebScanner/0.1"},
            )
        return self._client

    async def close(self) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None

    async def scan_url(
        self,
        url: str,
        method: str = "GET",
        params: dict[str, str] | None = None,
        body: str | None = None,
    ) -> list[Vulnerability]:
        """Scan complet d'une URL.

        Args:
            url: URL à scanner
            method: GET ou POST
            params: Paramètres de requête (pour GET)
            body: Corps de la requête (pour POST)

        """
        vulns: list[Vulnerability] = []
        client = await self._get_client()

        parsed = urlparse(url)
        base_params = params or {}
        if parsed.query:
            base_params.update(parse_qs(parsed.query))

        # 1. Headers de sécurité
        vulns.extend(await self._check_security_headers(client, url))

        # 2. Information disclosure dans la réponse normale
        vulns.extend(await self._check_info_disclosure(client, url))

        # 3. XSS
        vulns.extend(await self._check_xss(client, url, method, base_params, body))

        # 4. SQLi error-based
        vulns.extend(await self._check_sqli_error(client, url, method, base_params, body))

        # 5. SQLi time-based (si des paramètres sont présents)
        if base_params:
            vulns.extend(await self._check_sqli_time(client, url, method, base_params, body))

        # 6. Path traversal
        vulns.extend(await self._check_path_traversal(client, url))

        # 7. Open redirect
        vulns.extend(await self._check_open_redirect(client, url, base_params))

        return vulns

    # ------------------------------------------------------------------
    # Checks individuels
    # ------------------------------------------------------------------
    async def _check_security_headers(
        self,
        client: httpx.AsyncClient,
        url: str,
    ) -> list[Vulnerability]:
        vulns: list[Vulnerability] = []
        try:
            resp = await client.head(url)
            resp_headers_lower = {k.lower(): k for k in resp.headers}
            for header, (severity, description) in SECURITY_HEADERS.items():
                if header.lower() not in resp_headers_lower:
                    vulns.append(
                        Vulnerability(
                            name=f"Header sécurité manquant : {header}",
                            severity=severity,
                            url=url,
                            description=description,
                            remediation=f"Ajouter l'en-tête {header} dans la configuration du serveur",
                            cwe="CWE-693",
                        ),
                    )
        except (httpx.TimeoutException, httpx.RequestError, OSError) as e:
            logger.debug("scan_headers_échec", url=url, erreur=str(e))
        return vulns

    async def _check_info_disclosure(
        self,
        client: httpx.AsyncClient,
        url: str,
    ) -> list[Vulnerability]:
        vulns: list[Vulnerability] = []
        try:
            resp = await client.get(url)
            text = resp.text[:100_000]
            "\n".join(f"{k}: {v}" for k, v in resp.headers.items())

            for pattern, severity, template in INFO_DISCLOSURE_PATTERNS:
                for match in re.finditer(pattern, text, re.IGNORECASE):
                    evidence = match.group(0)[:200]
                    description = template.format(
                        header=match.group(1) if match.lastindex else evidence,
                        value=evidence,
                    )
                    vulns.append(
                        Vulnerability(
                            name="Information disclosure",
                            severity=severity,
                            url=url,
                            evidence=evidence,
                            description=description,
                            remediation="Supprimer les informations sensibles des réponses HTTP",
                            cwe="CWE-200",
                        ),
                    )
        except (httpx.TimeoutException, httpx.RequestError, OSError) as e:
            logger.debug("scan_info_échec", url=url, erreur=str(e))
        return vulns

    async def _check_xss(
        self,
        client: httpx.AsyncClient,
        url: str,
        method: str,
        params: dict[str, str],
        body: str | None,
    ) -> list[Vulnerability]:
        vulns: list[Vulnerability] = []
        if not params:
            return vulns

        for param_name in params:
            for payload in XSS_PAYLOADS[:3]:  # Limiter à 3 payloads par paramètre
                try:
                    test_params = dict(params)
                    test_params[param_name] = payload

                    if method.upper() == "GET":
                        parsed = urlparse(url)
                        new_query = urlencode(test_params)
                        new_parsed = parsed._replace(query=new_query)
                        test_url = urlunparse(new_parsed)
                        resp = await client.get(test_url)
                    else:
                        resp = await client.post(url, data=test_params)

                    if payload in resp.text:
                        vulns.append(
                            Vulnerability(
                                name="XSS reflété (Cross-Site Scripting)",
                                severity="high",
                                url=url,
                                parameter=param_name,
                                payload=payload,
                                evidence=f"Le payload {payload[:50]} est reflété dans la réponse",
                                description=f"Le paramètre '{param_name}' reflète le payload XSS sans échappement.",
                                remediation="Échapper les sorties HTML (htmlspecialchars, etc.) et valider les entrées.",
                                cwe="CWE-79",
                            ),
                        )
                        break  # Un seul payload suffit pour confirmer
                except (httpx.TimeoutException, httpx.RequestError, OSError):
                    continue

        return vulns

    async def _check_sqli_error(
        self,
        client: httpx.AsyncClient,
        url: str,
        method: str,
        params: dict[str, str],
        body: str | None,
    ) -> list[Vulnerability]:
        vulns: list[Vulnerability] = []
        if not params:
            return vulns

        for param_name in params:
            for payload in SQLI_ERROR_PAYLOADS[:4]:
                try:
                    test_params = dict(params)
                    test_params[param_name] = payload
                    if method.upper() == "GET":
                        parsed = urlparse(url)
                        new_parsed = parsed._replace(query=urlencode(test_params))
                        resp = await client.get(urlunparse(new_parsed))
                    else:
                        resp = await client.post(url, data=test_params)

                    for pattern in SQLI_ERROR_PATTERNS:
                        if re.search(pattern, resp.text, re.IGNORECASE):
                            vulns.append(
                                Vulnerability(
                                    name="SQL Injection (error-based)",
                                    severity="critical",
                                    url=url,
                                    parameter=param_name,
                                    payload=payload,
                                    evidence=f"Erreur SQL détectée : {pattern}",
                                    description=f"Injection SQL détectée via le paramètre '{param_name}'.",
                                    remediation="Utiliser des requêtes paramétrées (prepared statements).",
                                    cwe="CWE-89",
                                ),
                            )
                            return vulns  # Une seule suffit
                except (httpx.TimeoutException, httpx.RequestError, OSError):
                    continue
        return vulns

    async def _check_sqli_time(
        self,
        client: httpx.AsyncClient,
        url: str,
        method: str,
        params: dict[str, str],
        body: str | None,
    ) -> list[Vulnerability]:
        vulns: list[Vulnerability] = []
        if not params:
            return vulns

        for param_name in params:
            test_params = dict(params)
            test_params[param_name] = SQLI_TIME_PAYLOADS[0]  # SLEEP(2)

            try:
                t0 = time.monotonic()
                if method.upper() == "GET":
                    parsed = urlparse(url)
                    new_parsed = parsed._replace(query=urlencode(test_params))
                    await client.get(urlunparse(new_parsed))
                else:
                    await client.post(url, data=test_params)
                elapsed = time.monotonic() - t0

                if elapsed > 1.8:  # Le serveur a dormi ~2 secondes
                    vulns.append(
                        Vulnerability(
                            name="SQL Injection (time-based blind)",
                            severity="high",
                            url=url,
                            parameter=param_name,
                            payload=SQLI_TIME_PAYLOADS[0],
                            evidence=f"Temps de réponse anormal : {elapsed:.1f}s (attendu < 0.5s)",
                            description=f"Blind SQLi time-based via le paramètre '{param_name}'.",
                            remediation="Utiliser des requêtes paramétrées (prepared statements).",
                            cwe="CWE-89",
                        ),
                    )
            except (httpx.TimeoutException, httpx.RequestError, OSError):
                continue

        return vulns

    async def _check_path_traversal(
        self,
        client: httpx.AsyncClient,
        url: str,
    ) -> list[Vulnerability]:
        vulns: list[Vulnerability] = []
        parsed = urlparse(url)

        # Tester sur les paramètres de chemin (?file=, ?page=, ?path=)
        if not parsed.query:
            return vulns

        params = parse_qs(parsed.query)
        path_params = [
            k
            for k in params
            if any(
                hint in k.lower() for hint in ("file", "path", "page", "doc", "template", "include")
            )
        ]

        for param_name in path_params:
            for payload in PATH_TRAVERSAL_PAYLOADS[:4]:
                try:
                    test_params = dict(parse_qs(parsed.query))
                    test_params[param_name] = [payload]
                    new_parsed = parsed._replace(query=urlencode(test_params, doseq=True))
                    resp = await client.get(urlunparse(new_parsed))

                    for pattern in PATH_TRAVERSAL_PATTERNS:
                        if re.search(pattern, resp.text, re.IGNORECASE):
                            vulns.append(
                                Vulnerability(
                                    name="Path Traversal",
                                    severity="high",
                                    url=url,
                                    parameter=param_name,
                                    payload=payload,
                                    evidence=f"Contenu de fichier système détecté via {payload}",
                                    description=f"Lecture de fichiers arbitraires via le paramètre '{param_name}'.",
                                    remediation="Valider et sandboxer les chemins de fichiers. Utiliser des chemins canoniques.",
                                    cwe="CWE-22",
                                ),
                            )
                            return vulns
                except (httpx.TimeoutException, httpx.RequestError, OSError):
                    continue
        return vulns

    async def _check_open_redirect(
        self,
        client: httpx.AsyncClient,
        url: str,
        params: dict[str, str],
    ) -> list[Vulnerability]:
        vulns: list[Vulnerability] = []
        redirect_params = [
            k
            for k in params
            if any(
                hint in k.lower()
                for hint in ("redirect", "url", "next", "return", "goto", "target", "dest")
            )
        ]

        for param_name in redirect_params:
            for payload in OPEN_REDIRECT_PAYLOADS[:2]:
                try:
                    test_params = dict(params)
                    test_params[param_name] = payload
                    parsed = urlparse(url)
                    new_parsed = parsed._replace(query=urlencode(test_params))
                    resp = await client.get(urlunparse(new_parsed), follow_redirects=False)

                    if resp.status_code in (301, 302, 303, 307, 308):
                        location = resp.headers.get("Location", "")
                        if "evil.com" in location:
                            vulns.append(
                                Vulnerability(
                                    name="Open Redirect",
                                    severity="medium",
                                    url=url,
                                    parameter=param_name,
                                    payload=payload,
                                    evidence=f"Redirection vers {location}",
                                    description=f"Le paramètre '{param_name}' permet une redirection non validée.",
                                    remediation="Utiliser une whitelist de destinations ou des tokens de redirection.",
                                    cwe="CWE-601",
                                ),
                            )
                except (httpx.TimeoutException, httpx.RequestError, OSError):
                    continue
        return vulns
