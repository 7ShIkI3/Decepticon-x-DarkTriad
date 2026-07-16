"""Playwright Spider — crawler SPA/JavaScript pour NavMAX.

Contrairement au crawler standard (httpx + HTML statique), ce spider utilise
Playwright pour exécuter le JavaScript, attendre le rendu, et découvrir
les endpoints dynamiques invisibles au parsing HTML classique.

Usage:
    spider = PlaywrightSpider()
    results = await spider.crawl("https://app.example.com", max_depth=2)
"""

import asyncio
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

import structlog

logger = structlog.get_logger(__name__)


class PlaywrightNotAvailableError(Exception):
    """Playwright n'est pas installé."""

    def __init__(self, message: str = "Playwright n'est pas installé") -> None:
        super().__init__(message)


# ── Types ────────────────────────────────────────────────────────


@dataclass
class SPAEndpoint:
    """Un endpoint découvert par le spider SPA."""

    url: str
    method: str = "GET"
    params: list[str] = field(default_factory=list)
    source: str = ""  # "link", "fetch", "xhr", "websocket", "route"
    status_code: int = 0
    content_type: str = ""
    screenshot: str | None = None  # Chemin screenshot si pris


@dataclass
class SPACrawlResult:
    """Résultat complet d'un crawl SPA."""

    base_url: str
    visited_pages: int
    discovered_endpoints: list[SPAEndpoint]
    javascript_errors: list[dict]  # {url, message, line}
    console_logs: list[dict]  # {url, level, text}
    api_calls_captured: int
    websocket_endpoints: list[str]
    duration_ms: float


# ── Spider ───────────────────────────────────────────────────────


class PlaywrightSpider:
    """Crawler SPA avec Playwright.

    Caractéristiques :
    - Rend JavaScript et attend les requêtes réseau
    - Capture les appels XHR/fetch/WebSocket
    - Suit les liens du DOM après rendu
    - Screenshot automatique des pages suspectes
    - Fallback vers le crawler httpx si Playwright pas installé
    """

    def __init__(
        self,
        headless: bool = True,
        timeout: int = 30000,
        max_concurrent: int = 3,
        user_agent: str = (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/125.0.0.0 Safari/537.36"
        ),
    ) -> None:
        self.headless = headless
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self.user_agent = user_agent
        self._playwright_available = False
        self._checked = False

    def _check_playwright(self) -> bool:
        """Vérifie si Playwright est installé (une seule fois)."""
        if self._checked:
            return self._playwright_available
        self._checked = True
        try:
            import playwright  # noqa: F401

            self._playwright_available = True
            logger.info("playwright_spider_disponible")
            return True
        except ImportError:
            logger.warning(
                "playwright_non_installé",
                conseil="pip install playwright && playwright install chromium",
            )
            return False

    async def crawl(
        self,
        base_url: str,
        max_depth: int = 2,
        max_pages: int = 50,
        capture_screenshots: bool = False,
    ) -> SPACrawlResult:
        """Lance un crawl SPA.

        Args:
            base_url: URL de départ
            max_depth: Profondeur maximale de crawl
            max_pages: Nombre max de pages à visiter
            capture_screenshots: Prendre des screenshots

        """
        if not self._check_playwright():
            msg = (
                "Playwright n'est pas installé. "
                "pip install playwright && playwright install chromium"
            )
            raise PlaywrightNotAvailableError(
                msg,
            )

        import playwright.async_api as pw

        start_time = asyncio.get_event_loop().time()

        domain = urlparse(base_url).netloc
        visited: set[str] = set()
        to_visit: list[tuple[str, int]] = [(base_url, 0)]
        endpoints: list[SPAEndpoint] = []
        js_errors: list[dict] = []
        console_logs: list[dict] = []
        ws_endpoints: set[str] = set()

        semaphore = asyncio.Semaphore(self.max_concurrent)

        async with pw.async_playwright() as p:
            browser = await p.chromium.launch(
                headless=self.headless,
                args=["--no-sandbox", "--disable-setuid-sandbox"],
            )
            context = await browser.new_context(
                user_agent=self.user_agent,
                viewport={"width": 1280, "height": 720},
            )

            try:

                async def visit_page(url: str, depth: int) -> None:
                    if url in visited or len(visited) >= max_pages:
                        return
                    visited.add(url)

                    async with semaphore:
                        page = await context.new_page()

                        # Capture des événements réseau
                        captured_requests: list[dict] = []

                        async def on_request(request: pw.Request) -> None:
                            if request.resource_type in ("xhr", "fetch"):
                                captured_requests.append(
                                    {
                                        "url": request.url,
                                        "method": request.method,
                                        "resource_type": request.resource_type,
                                    },
                                )

                        async def on_response(response: pw.Response) -> None:
                            req_url = response.url
                            # Ignorer les ressources statiques
                            if any(
                                ext in req_url
                                for ext in (
                                    ".js",
                                    ".css",
                                    ".png",
                                    ".jpg",
                                    ".woff",
                                    ".ico",
                                )
                            ):
                                return
                            if req_url.startswith(base_url) and response.status < 400:
                                ep = SPAEndpoint(
                                    url=req_url,
                                    method=response.request.method,
                                    status_code=response.status_code,
                                    source=response.request.resource_type,
                                )
                                endpoints.append(ep)

                        page.on("request", on_request)
                        page.on("response", on_response)

                        # Capture console et erreurs
                        async def on_console(msg: pw.ConsoleMessage) -> None:
                            console_logs.append(
                                {
                                    "url": url,
                                    "level": msg.type,
                                    "text": msg.text,
                                },
                            )

                        async def on_pageerror(error: pw.Error) -> None:
                            js_errors.append(
                                {
                                    "url": url,
                                    "message": str(error),
                                },
                            )

                        page.on("console", on_console)
                        page.on("pageerror", on_pageerror)

                        try:
                            await page.goto(
                                url,
                                wait_until="networkidle",
                                timeout=self.timeout,
                            )

                            # Capturer les WebSocket
                            ws_urls = await page.evaluate("""
                                () => {
                                    const wss = [];
                                    try {
                                        const entries = performance.getEntriesByType('resource');
                                        for (const e of entries) {
                                            if (e.initiatorType === 'websocket') wss.push(e.name);
                                        }
                                    } catch(_) {}
                                    return wss;
                                }
                            """)
                            ws_endpoints.update(ws_urls)

                            if capture_screenshots and depth == 0:
                                import tempfile

                                fname = tempfile.mktemp(suffix=".png", prefix="navmax_spa_")
                                await page.screenshot(path=fname, full_page=True)
                                for ep in endpoints:
                                    if ep.source in {"xhr", "fetch"}:
                                        ep.screenshot = fname

                            # Découvrir les liens pour crawler plus loin
                            if depth < max_depth:
                                links = await page.evaluate("""
                                    () => {
                                        const anchors = document.querySelectorAll(
                                            'a[href]:not([href^="javascript"]):not([href^="mailto"])'
                                        );
                                        return Array.from(anchors).map(a => a.href);
                                    }
                                """)
                                for link in links:
                                    parsed = urlparse(link)
                                    if parsed.netloc == domain:
                                        clean_link = link.split("#")[0]
                                        if clean_link not in visited:
                                            to_visit.append((clean_link, depth + 1))

                            # Extraire les formulaires
                            forms = await page.evaluate("""
                                () => {
                                    const fs = document.querySelectorAll('form');
                                    return Array.from(fs).map(f => ({
                                        action: f.action || '',
                                        method: (f.method || 'GET').toUpperCase(),
                                        inputs: Array.from(
                                            f.querySelectorAll('input,select,textarea')
                                        ).map(i => ({
                                            name: i.name || '',
                                            type: i.type || 'text'
                                        }))
                                    }));
                                }
                            """)
                            for form in forms:
                                for inp in form["inputs"]:
                                    ename = inp["name"]
                                    if ename:
                                        endpoint_url = (
                                            urljoin(url, form["action"]) if form["action"] else url
                                        )
                                        endpoints.append(
                                            SPAEndpoint(
                                                url=endpoint_url,
                                                method=form["method"],
                                                params=[ename],
                                                source="form",
                                            ),
                                        )

                        except pw.TimeoutError:
                            logger.warning("page_timeout", url=url)
                        except Exception as e:
                            logger.exception("page_error", url=url, error=str(e))
                        finally:
                            await page.close()

                # Visiter tout ce qu'on a découvert
                while to_visit and len(visited) < max_pages:
                    # Prendre les URLs non visitées
                    batch = []
                    while to_visit and len(batch) < self.max_concurrent:
                        url, depth = to_visit.pop(0)
                        if url not in visited:
                            batch.append((url, depth))

                    if batch:
                        await asyncio.gather(*[visit_page(url, depth) for url, depth in batch])

            finally:
                await browser.close()

        elapsed = (asyncio.get_event_loop().time() - start_time) * 1000

        return SPACrawlResult(
            base_url=base_url,
            visited_pages=len(visited),
            discovered_endpoints=endpoints,
            javascript_errors=js_errors,
            console_logs=console_logs,
            api_calls_captured=sum(1 for ep in endpoints if ep.source in ("xhr", "fetch")),
            websocket_endpoints=list(ws_endpoints),
            duration_ms=elapsed,
        )


# ── Intégration avec le crawler existant ────────────────────────


async def crawl_with_fallback(
    base_url: str,
    max_depth: int = 2,
    prefer_spa: bool = True,
) -> SPACrawlResult | None:
    """Tente le crawl SPA, fallback vers httpx si Playwright indisponible.

    Returns:
        SPACrawlResult si Playwright dispo, None sinon (utiliser crawler standard)

    """
    spider = PlaywrightSpider()
    try:
        return await spider.crawl(base_url, max_depth=max_depth)
    except PlaywrightNotAvailableError:
        logger.info("fallback_crawler_httpx", url=base_url)
        return None
