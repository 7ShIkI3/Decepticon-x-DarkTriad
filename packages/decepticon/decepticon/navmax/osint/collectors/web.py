"""Collecteur web — scraping léger pour technologies, emails, liens."""

import re
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

import httpx

from decepticon.navmax.core.logging import get_logger

logger = get_logger(__name__)


@dataclass
class WebTechInfo:
    url: str
    server: str | None = None
    technologies: list[str] = field(default_factory=list)
    emails_found: list[str] = field(default_factory=list)
    links_external: list[str] = field(default_factory=list)
    title: str | None = None
    status_code: int = 0
    social_links: dict[str, str] = field(default_factory=dict)


# Patterns de détection de technologies
TECH_PATTERNS: dict[str, list[str]] = {
    "WordPress": [r"wp-content", r"wp-includes", r"wordpress"],
    "Drupal": [r"Drupal", r"drupal\.js"],
    "Joomla": [r"Joomla", r"joomla"],
    "jQuery": [r"jquery[\-.]([0-9.]+)", r"jquery"],
    "Bootstrap": [r"bootstrap[\-.]([0-9.]+)", r"bootstrap\.min\.css"],
    "React": [r"react[\-.]([0-9.]+)", r"react\.js", r"react.production"],
    "Vue.js": [r"vue[\-.]([0-9.]+)", r"vue\.js"],
    "Angular": [r"angular[\-.]([0-9.]+)", r"ng-app"],
    "nginx": [r"nginx/([0-9.]+)"],
    "Apache": [r"Apache/([0-9.]+)", r"Apache/2"],
    "Cloudflare": [r"cloudflare", r"cf-ray"],
    "PHP": [r"PHP/([0-9.]+)", r"\.php"],
    "Django": [r"csrftoken", r"django"],
    "Laravel": [r"laravel_session", r"laravel"],
    "ASP.NET": [r"ASP\.NET", r"__VIEWSTATE"],
    "Ruby on Rails": [r"rails", r"_session_id"],
    "Node.js": [r"node\.js", r"express"],
    "Google Analytics": [r"google-analytics\.com", r"ga\.js", r"gtag"],
    "Font Awesome": [r"font-?awesome"],
    "Tailwind CSS": [r"tailwindcss", r"tailwind\.css"],
}

# Patterns de découverte d'emails
EMAIL_PATTERN = re.compile(
    r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
    re.IGNORECASE,
)

# Patterns de liens sociaux
SOCIAL_PATTERNS: dict[str, str] = {
    "github": r"github\.com/([\w\-]+)",
    "linkedin": r"linkedin\.com/company/([\w\-]+)",
    "twitter": r"twitter\.com/([\w\-]+)",
    "facebook": r"facebook\.com/([\w\-.]+)",
    "instagram": r"instagram\.com/([\w\-.]+)",
    "youtube": r"youtube\.com/(?:@|channel/|c/)?([\w\-]+)",
}


class WebCollector:
    """Collecteur web — scraping léger."""

    def __init__(self, timeout: float = 15.0) -> None:
        self.timeout = timeout
        self._client: httpx.AsyncClient | None = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                verify=False,
                timeout=httpx.Timeout(self.timeout),
                follow_redirects=True,
                headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 NavMAX OSINT/0.1",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Accept-Language": "en-US,en;q=0.5",
                },
            )
        return self._client

    async def close(self) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None

    async def analyze(self, url: str) -> WebTechInfo | None:
        """Analyse une page web : technologies, emails, liens."""
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        client = await self._get_client()
        info = WebTechInfo(url=url)

        try:
            resp = await client.get(url)
            info.status_code = resp.status_code

            if resp.status_code >= 400:
                return info

            text = resp.text[:500_000]  # 500 Ko max
            info.server = resp.headers.get("Server")

            # Titre
            m = re.search(r"<title[^>]*>(.*?)</title>", text, re.IGNORECASE | re.DOTALL)
            if m:
                info.title = m.group(1).strip()[:200]

            # Technologies
            for tech, patterns in TECH_PATTERNS.items():
                for pat in patterns:
                    if re.search(pat, text, re.IGNORECASE):
                        info.technologies.append(tech)
                        break
            info.technologies = list(dict.fromkeys(info.technologies))  # dédoublonner

            # Emails
            emails = EMAIL_PATTERN.findall(text)
            seen_emails: set[str] = set()
            for email in emails:
                if email.lower() not in seen_emails and len(email) < 100:
                    # Filtrer les faux positifs
                    if not any(
                        fake in email.lower()
                        for fake in ("example.com", "domain.com", "email.com", "@example")
                    ):
                        info.emails_found.append(email.lower())
                        seen_emails.add(email.lower())

            # Liens externes
            parsed_base = urlparse(url)
            base_domain = parsed_base.netloc.lower()
            for link_match in re.finditer(r'href=["\']([^"\']+)["\']', text, re.IGNORECASE):
                link = link_match.group(1)
                absolute = urljoin(url, link)
                parsed = urlparse(absolute)
                if parsed.netloc and parsed.netloc.lower() != base_domain:
                    if absolute not in info.links_external:
                        info.links_external.append(absolute)

            # Réseaux sociaux
            for platform, pat in SOCIAL_PATTERNS.items():
                m = re.search(pat, text, re.IGNORECASE)
                if m:
                    info.social_links[platform] = f"https://{platform}.com/{m.group(1)}"

            info.links_external = info.links_external[:30]
            info.emails_found = info.emails_found[:20]

        except (TimeoutError, httpx.RequestError) as e:
            logger.debug("web_échec", url=url, erreur=str(e))

        return info
