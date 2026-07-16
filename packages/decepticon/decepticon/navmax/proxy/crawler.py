"""Proxy crawler — découverte automatique d'endpoints sur une application web.

Fonctionnalités :
- Crawling récursif des liens internes
- Détection de formulaires et paramètres
- Découverte de fichiers/dossiers cachés (dir busting)
- Analyse du sitemap et robots.txt
- Détection des technologies utilisées
"""

import asyncio
import re
import urllib.parse
from collections import deque
from dataclasses import dataclass, field

import httpx

from decepticon.navmax.core.logging import get_logger

logger = get_logger(__name__)


@dataclass
class CrawlResult:
    """Résultat d'un crawl."""

    url: str
    status_code: int
    content_type: str = ""
    content_length: int = 0
    title: str = ""
    links: list[str] = field(default_factory=list)
    forms: list[dict] = field(default_factory=list)
    params: list[str] = field(default_factory=list)
    headers: dict[str, str] = field(default_factory=dict)
    technologies: list[str] = field(default_factory=list)
    depth: int = 0
    error: str | None = None


@dataclass
class CrawlReport:
    """Rapport de crawling complet."""

    base_url: str
    crawled_urls: int
    discovered_endpoints: list[CrawlResult]
    total_forms: int
    total_params: int
    technologies_detected: set[str]
    directories_found: list[str]
    duration_ms: float = 0


# ---------------------------------------------------------------------------
# Common dir busting wordlist
# ---------------------------------------------------------------------------
COMMON_PATHS = [
    "admin",
    "login",
    "wp-admin",
    "backup",
    "config",
    "test",
    "api",
    "api/v1",
    "graphql",
    "swagger",
    "docs",
    "phpmyadmin",
    ".git",
    ".env",
    ".svn",
    ".hg",
    "robots.txt",
    "sitemap.xml",
    "crossdomain.xml",
    "phpinfo.php",
    "info.php",
    "server-status",
    "status",
    "health",
    "metrics",
    "debug",
    "console",
    "actuator",
    "wp-content",
    "wp-includes",
    "administrator",
    "web.config",
    "docker-compose.yml",
    "composer.json",
    "package.json",
    "src",
    "dist",
    "build",
    "node_modules",
    "uploads",
    "images",
    "assets",
    "static",
    "public",
    "tmp",
    "temp",
    "log",
    "logs",
    "error.log",
    "access.log",
    "old",
    "new",
    "v1",
    "v2",
    "dev",
    "staging",
    "beta",
    "api-docs",
    "openapi.json",
    "spec.json",
]


class Crawler:
    """Crawler web pour la découverte d'endpoints.

    Usage:
        crawler = Crawler(max_depth=3, max_urls=100)
        report = await crawler.crawl("https://target.com")
        for ep in report.discovered_endpoints:
            print(f"{ep.url} [{ep.status_code}] {ep.title}")
    """

    def __init__(
        self,
        max_depth: int = 3,
        max_urls: int = 200,
        concurrency: int = 10,
        timeout: float = 10.0,
        follow_redirects: bool = True,
        dir_bust: bool = True,
        user_agent: str = "NavMAX-Crawler/1.0",
    ) -> None:
        self.max_depth = max_depth
        self.max_urls = max_urls
        self.concurrency = concurrency
        self.timeout = timeout
        self.follow_redirects = follow_redirects
        self.dir_bust = dir_bust
        self.user_agent = user_agent

        self._visited: set[str] = set()
        self._results: dict[str, CrawlResult] = {}
        self._semaphore = asyncio.Semaphore(concurrency)
        self._client: httpx.AsyncClient | None = None

    def _is_internal(self, url: str, base_domain: str) -> bool:
        """Vérifie si une URL est interne au domaine cible."""
        parsed = urllib.parse.urlparse(url)
        if not parsed.netloc:
            return True  # URL relative
        return parsed.netloc.endswith(base_domain) or base_domain in parsed.netloc

    def _extract_links(self, html: str, base_url: str) -> list[str]:
        """Extrait les liens d'une page HTML."""
        links = set()
        # href dans <a>
        for m in re.finditer(r'href=["\']([^"\']+)["\']', html, re.IGNORECASE):
            href = m.group(1)
            if not href.startswith(("javascript:", "mailto:", "tel:", "#")):
                full = urllib.parse.urljoin(base_url, href)
                links.add(full)

        # src dans <script>, <img>
        for m in re.finditer(r'src=["\']([^"\']+)["\']', html, re.IGNORECASE):
            src = m.group(1)
            if not src.startswith("data:"):
                full = urllib.parse.urljoin(base_url, src)
                links.add(full)

        return list(links)

    def _extract_forms(self, html: str) -> list[dict]:
        """Extrait les formulaires et leurs paramètres."""
        forms = []
        for m in re.finditer(r"<form[^>]*>", html, re.IGNORECASE):
            form_tag = m.group(0)
            action = ""
            method = "GET"
            action_m = re.search(r'action=["\']([^"\']+)["\']', form_tag, re.IGNORECASE)
            if action_m:
                action = action_m.group(1)
            method_m = re.search(r'method=["\']([^"\']+)["\']', form_tag, re.IGNORECASE)
            if method_m:
                method = method_m.group(1).upper()

            # Extraire les inputs
            inputs = []
            for im in re.finditer(r"<input[^>]*>", html, re.IGNORECASE):
                input_tag = im.group(0)
                name_m = re.search(r'name=["\']([^"\']+)["\']', input_tag, re.IGNORECASE)
                type_m = re.search(r'type=["\']([^"\']+)["\']', input_tag, re.IGNORECASE)
                if name_m:
                    inputs.append(
                        {
                            "name": name_m.group(1),
                            "type": type_m.group(1) if type_m else "text",
                        },
                    )

            forms.append(
                {
                    "action": action,
                    "method": method,
                    "inputs": inputs,
                },
            )

        return forms

    def _detect_technologies(self, headers: dict[str, str], html: str) -> list[str]:
        """Détecte les technologies utilisées."""
        techs = []

        tech_patterns: dict[str, list[str]] = {
            "jQuery": [r"jquery[.\-\s]*(\d+\.\d+\.\d+)"],
            "React": [r"react[.\-\s]*(\d+\.\d+)", r"reactjs"],
            "Vue.js": [r"vue[.\-\s]*(\d+\.\d+)", r"v-bind"],
            "Angular": [r"ng-app", r"angular[.\-\s]*(\d+\.\d+)"],
            "Bootstrap": [r"bootstrap[.\-\s]*(\d+\.\d+)"],
            "WordPress": [r"wp-content", r"wordpress"],
            "Django": [r"__django", r"csrftoken"],
            "Laravel": [r"laravel_session"],
            "Express": [r"x-powered-by.*express", r"connect.sid"],
            "PHP": [r"\.php", r"PHPSESSID"],
            "ASP.NET": [r"__VIEWSTATE", r"ASP.NET_SessionId"],
            "Nginx": [r"nginx"],
            "Apache": [r"apache"],
            "Cloudflare": [r"cloudflare"],
            "AWS": [r"aws-", r"x-amz-"],
        }

        server_header = headers.get("server", "")
        powered_by = headers.get("x-powered-by", "")

        for tech, patterns in tech_patterns.items():
            for pat in patterns:
                if (
                    re.search(pat, html, re.IGNORECASE)
                    or re.search(pat, server_header, re.IGNORECASE)
                    or re.search(pat, powered_by, re.IGNORECASE)
                ):
                    techs.append(tech)
                    break

        return techs

    async def _fetch(self, url: str, depth: int) -> CrawlResult | None:
        """Fetch une URL et extrait les infos."""
        async with self._semaphore:
            try:
                if self._client is None:
                    return None
                resp = await self._client.get(
                    url,
                    headers={"User-Agent": self.user_agent},
                    follow_redirects=self.follow_redirects,
                )
                html = resp.text
                links = self._extract_links(html, url)
                forms = self._extract_forms(html)
                title_m = re.search(r"<title[^>]*>([^<]+)</title>", html, re.IGNORECASE)
                title = title_m.group(1).strip() if title_m else ""
                params = list({p for p in re.findall(r"[?&]([^=&\s]+)=", url) if p})
                techs = self._detect_technologies(dict(resp.headers), html)

                return CrawlResult(
                    url=url,
                    status_code=resp.status_code,
                    content_type=resp.headers.get("content-type", ""),
                    content_length=len(resp.content),
                    title=title,
                    links=links,
                    forms=forms,
                    params=params,
                    headers=dict(resp.headers),
                    technologies=techs,
                    depth=depth,
                )
            except (httpx.TimeoutException, httpx.RequestError, OSError) as e:
                return CrawlResult(url=url, status_code=0, depth=depth, error=str(e))
            except Exception as e:
                logger.debug("fetch_erreur_inattendue", url=url, erreur=str(e))
                return CrawlResult(url=url, status_code=0, depth=depth, error=str(e))

    async def crawl(self, base_url: str) -> CrawlReport:
        """Lance le crawling sur une URL de départ."""
        import time

        start = time.time()

        base_url = base_url.rstrip("/")
        parsed_base = urllib.parse.urlparse(base_url)
        base_domain = parsed_base.netloc or parsed_base.path.split("/")[0]

        self._visited = set()
        self._results = {}

        queue: deque[tuple[str, int]] = deque()
        queue.append((base_url, 0))

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            self._client = client

            while queue and len(self._visited) < self.max_urls:
                # Traiter par lots
                batch = []
                while queue and len(batch) < self.concurrency:
                    batch.append(queue.popleft())

                tasks = []
                for url, depth in batch:
                    if url in self._visited:
                        continue
                    if not self._is_internal(url, base_domain):
                        continue
                    if depth > self.max_depth:
                        continue
                    self._visited.add(url)
                    tasks.append(self._fetch(url, depth))

                results = await asyncio.gather(*tasks)

                for result in results:
                    if result is None:
                        continue
                    self._results[result.url] = result

                    if result.depth < self.max_depth and result.status_code == 200:
                        for link in result.links:
                            if link not in self._visited:
                                queue.append((link, result.depth + 1))

        # Dir busting
        directories_found: list[str] = []
        if self.dir_bust:
            dir_tasks = []
            for path in COMMON_PATHS:
                url = f"{base_url}/{path}"
                if url not in self._visited:
                    self._visited.add(url)
                    dir_tasks.append(self._fetch(url, 99))  # depth 99 = dir bust

            dir_results = await asyncio.gather(*dir_tasks)
            for result in dir_results:
                if result and result.status_code not in (0, 404):
                    self._results[result.url] = result
                    if result.status_code in (200, 301, 302, 403):
                        directories_found.append(result.url)

        elapsed = (time.time() - start) * 1000

        all_techs = set()
        total_forms = 0
        total_params = 0
        for r in self._results.values():
            all_techs.update(r.technologies)
            total_forms += len(r.forms)
            total_params += len(r.params)

        self._client = None

        logger.info(
            "crawl_terminé",
            base_url=base_url,
            crawled=len(self._visited),
            endpoints=len(self._results),
            dirs=len(directories_found),
            duration_ms=round(elapsed, 0),
        )

        return CrawlReport(
            base_url=base_url,
            crawled_urls=len(self._visited),
            discovered_endpoints=list(self._results.values()),
            total_forms=total_forms,
            total_params=total_params,
            technologies_detected=all_techs,
            directories_found=directories_found,
            duration_ms=elapsed,
        )
