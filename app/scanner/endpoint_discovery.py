import re
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import requests
from app.security.target_validator import TargetValidator, TargetValidationError


class EndpointDiscoveryEngine:
    """Safe In-Scope Web Asset and Endpoint Discovery Engine.
    
    Extracts authorized endpoints passively from:
    1. Rendered HTML anchor tags (<a href>)
    2. Form action endpoints (<form action>) - Safe inventory only; never submits forms!
    3. External/Internal JavaScript source links (<script src>)
    4. robots.txt Disallow and Allow directives
    5. sitemap.xml <loc> entries
    
    Guarantees strict domain-scope isolation and prevents SSRF during secondary crawls.
    """

    MAX_ENDPOINTS = 200
    DEFAULT_TIMEOUT = 5.0
    DEFAULT_USER_AGENT = "AppSentinel-Discovery/2.0 (Endpoint Auditor; +https://appsentinel.local)"

    @classmethod
    def is_in_scope(cls, candidate_url: str, authorized_domain: str) -> bool:
        """Verify URL belongs to the authorized target domain or its subdomains."""
        try:
            parsed = urlparse(candidate_url)
            if not parsed.hostname:
                return False
            host = parsed.hostname.lower()
            auth = authorized_domain.lower()
            return host == auth or host.endswith("." + auth)
        except Exception:
            return False

    @classmethod
    def clean_url(cls, raw_url: str) -> str | None:
        """Strip fragments, normalize path, reject mailto/javascript/tel/data schemes."""
        if not raw_url or not isinstance(raw_url, str):
            return None
        cleaned = raw_url.strip()
        if cleaned.startswith(("#", "javascript:", "mailto:", "tel:", "data:", "blob:")):
            return None
        # Remove fragment
        return cleaned.split("#")[0]

    @classmethod
    def extract_from_html(
        cls, html_content: str, base_url: str, authorized_domain: str
    ) -> list[dict]:
        """Extract links, forms, and script sources from HTML body."""
        endpoints = []
        seen = set()

        if not html_content:
            return endpoints

        try:
            soup = BeautifulSoup(html_content[:1000000], "html.parser")
        except Exception:
            return endpoints

        # 1. HTML Links
        for tag in soup.find_all("a", href=True):
            cleaned = cls.clean_url(tag["href"])
            if not cleaned:
                continue
            abs_url = urljoin(base_url, cleaned)
            if cls.is_in_scope(abs_url, authorized_domain) and abs_url not in seen:
                seen.add(abs_url)
                endpoints.append({
                    "url": abs_url,
                    "http_method": "GET",
                    "source": "html_link",
                    "status_code": None,
                    "content_type": None,
                })

        # 2. Form Actions
        for form in soup.find_all("form", action=True):
            action = cls.clean_url(form.get("action", ""))
            method = form.get("method", "GET").upper()
            if not action:
                abs_url = base_url
            else:
                abs_url = urljoin(base_url, action)

            if cls.is_in_scope(abs_url, authorized_domain) and (abs_url, method) not in seen:
                seen.add((abs_url, method))
                endpoints.append({
                    "url": abs_url,
                    "http_method": method,
                    "source": "form_action",
                    "status_code": None,
                    "content_type": None,
                })

        # 3. Scripts
        for script in soup.find_all("script", src=True):
            cleaned = cls.clean_url(script["src"])
            if not cleaned:
                continue
            abs_url = urljoin(base_url, cleaned)
            if cls.is_in_scope(abs_url, authorized_domain) and abs_url not in seen:
                seen.add(abs_url)
                endpoints.append({
                    "url": abs_url,
                    "http_method": "GET",
                    "source": "script",
                    "status_code": None,
                    "content_type": "application/javascript",
                })

        return endpoints

    @classmethod
    def extract_from_robots(
        cls, base_url: str, authorized_domain: str, timeout: float = DEFAULT_TIMEOUT, allow_private: bool = False
    ) -> list[dict]:
        """Safely fetch and parse robots.txt for disallowed or allowed paths."""
        robots_url = urljoin(base_url, "/robots.txt")
        try:
            TargetValidator.validate_target_url(robots_url, allow_private=allow_private)
            resp = requests.get(
                robots_url,
                timeout=timeout,
                headers={"User-Agent": cls.DEFAULT_USER_AGENT},
                allow_redirects=False,
            )
            if resp.status_code != 200 or "text" not in resp.headers.get("Content-Type", ""):
                return []
        except Exception:
            return []

        endpoints = []
        for line in resp.text.splitlines():
            line = line.strip()
            if line.startswith("#") or not line:
                continue
            if line.lower().startswith(("disallow:", "allow:")):
                parts = line.split(":", 1)
                if len(parts) == 2:
                    path = parts[1].strip()
                    if path and not path.startswith("*"):
                        full_url = urljoin(base_url, path)
                        if cls.is_in_scope(full_url, authorized_domain):
                            endpoints.append({
                                "url": full_url,
                                "http_method": "GET",
                                "source": "robots_txt",
                                "status_code": None,
                                "content_type": None,
                            })
        return endpoints

    @classmethod
    def extract_from_sitemap(
        cls, base_url: str, authorized_domain: str, timeout: float = DEFAULT_TIMEOUT, allow_private: bool = False
    ) -> list[dict]:
        """Safely fetch and parse sitemap.xml for referenced URLs."""
        sitemap_url = urljoin(base_url, "/sitemap.xml")
        try:
            TargetValidator.validate_target_url(sitemap_url, allow_private=allow_private)
            resp = requests.get(
                sitemap_url,
                timeout=timeout,
                headers={"User-Agent": cls.DEFAULT_USER_AGENT},
                allow_redirects=False,
            )
            if resp.status_code != 200:
                return []
        except Exception:
            return []

        endpoints = []
        loc_urls = re.findall(r"<loc>(https?://[^<]+)</loc>", resp.text, re.IGNORECASE)
        for loc in loc_urls:
            loc_clean = loc.strip()
            if cls.is_in_scope(loc_clean, authorized_domain):
                endpoints.append({
                    "url": loc_clean,
                    "http_method": "GET",
                    "source": "sitemap_xml",
                    "status_code": None,
                    "content_type": None,
                })
        return endpoints

    @classmethod
    def discover_all(
        cls,
        base_url: str,
        authorized_domain: str,
        html_content: str = "",
        timeout: float = DEFAULT_TIMEOUT,
        allow_private: bool = False,
    ) -> list[dict]:
        """Execute unified endpoint discovery across HTML, robots.txt, and sitemap.xml."""
        discovered: dict[tuple[str, str], dict] = {}

        def add_all(items):
            for it in items:
                key = (it["url"], it["http_method"])
                if key not in discovered and len(discovered) < cls.MAX_ENDPOINTS:
                    discovered[key] = it

        # 1. Base URL itself
        add_all([{
            "url": base_url,
            "http_method": "GET",
            "source": "html_link",
            "status_code": 200,
            "content_type": "text/html",
        }])

        # 2. HTML parsing
        if html_content:
            add_all(cls.extract_from_html(html_content, base_url, authorized_domain))

        # 3. robots.txt
        add_all(cls.extract_from_robots(base_url, authorized_domain, timeout=timeout, allow_private=allow_private))

        # 4. sitemap.xml
        add_all(cls.extract_from_sitemap(base_url, authorized_domain, timeout=timeout, allow_private=allow_private))

        return list(discovered.values())
