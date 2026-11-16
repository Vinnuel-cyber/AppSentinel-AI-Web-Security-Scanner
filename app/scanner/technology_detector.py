import re
from bs4 import BeautifulSoup


class TechnologyDetector:
    """Enterprise Passive Technology Detection Engine.
    
    Identifies servers, web frameworks, programming languages, CMS platforms,
    JavaScript frameworks, and CDN/Cloud infrastructures from passive HTTP response data.
    """

    # Cookie name signatures mapping to (Category, Name, Confidence)
    COOKIE_SIGNATURES = {
        "phpsessid": ("language", "PHP", "HIGH"),
        "jsessionid": ("language", "Java", "HIGH"),
        "asp.net_sessionid": ("framework", "ASP.NET", "HIGH"),
        "laravel_session": ("framework", "Laravel", "HIGH"),
        "csrftoken": ("framework", "Django", "MEDIUM"),
        "sessionid": ("framework", "Django", "LOW"),
        "connect.sid": ("framework", "Express.js", "HIGH"),
        "rack.session": ("framework", "Ruby on Rails", "HIGH"),
        "_rails_admin_session": ("framework", "Ruby on Rails", "HIGH"),
        "wordpress_logged_in": ("cms", "WordPress", "HIGH"),
        "wp-settings": ("cms", "WordPress", "HIGH"),
        "drupal": ("cms", "Drupal", "MEDIUM"),
        "joomla": ("cms", "Joomla", "MEDIUM"),
    }

    # Header-based technology signatures
    HEADER_SIGNATURES = [
        # Server headers
        ("server", r"nginx(?:/([\d.]+))?", "server", "Nginx"),
        ("server", r"apache(?:/([\d.]+))?", "server", "Apache HTTP Server"),
        ("server", r"microsoft-iis(?:/([\d.]+))?", "server", "Microsoft IIS"),
        ("server", r"cloudflare", "cdn", "Cloudflare"),
        ("server", r"caddy(?: v?([\d.]+))?", "server", "Caddy"),
        ("server", r"litespeed", "server", "LiteSpeed Web Server"),
        ("server", r"openresty(?:/([\d.]+))?", "server", "OpenResty"),
        ("server", r"gunicorn(?:/([\d.]+))?", "server", "Gunicorn"),
        ("server", r"uvicorn", "server", "Uvicorn"),
        ("server", r"werkzeug(?:/([\d.]+))?", "server", "Werkzeug / Flask"),
        # X-Powered-By
        ("x-powered-by", r"php(?:/([\d.]+))?", "language", "PHP"),
        ("x-powered-by", r"asp\.net", "framework", "ASP.NET"),
        ("x-powered-by", r"express", "framework", "Express.js"),
        ("x-powered-by", r"next\.js(?: ([\d.]+))?", "framework", "Next.js"),
        ("x-powered-by", r"wp engine", "cms", "WordPress"),
        # CDN / Cloud headers
        ("cf-ray", r".*", "cdn", "Cloudflare"),
        ("x-amz-cf-id", r".*", "cdn", "Amazon CloudFront"),
        ("x-fastly-request-id", r".*", "cdn", "Fastly"),
        ("x-akamai-transformed", r".*", "cdn", "Akamai"),
        ("x-vercel-id", r".*", "cdn", "Vercel"),
        ("x-drupal-cache", r".*", "cms", "Drupal"),
        ("x-generator", r"drupal(?: ([\d.]+))?", "cms", "Drupal"),
        ("x-generator", r"wordpress(?: ([\d.]+))?", "cms", "WordPress"),
        ("x-generator", r"joomla!? ([\d.]+)?", "cms", "Joomla"),
    ]

    # HTML Body and Script signatures
    SCRIPT_SIGNATURES = [
        (r"jquery(?:-([0-9.]+))?(?:\.min)?\.js", "js_library", "jQuery"),
        (r"react(?:-dom)?(?:\.production|\.development)?(?:\.min)?\.js", "js_library", "React"),
        (r"vue(?:\.runtime)?(?:\.min)?\.js", "js_library", "Vue.js"),
        (r"angular(?:\.min)?\.js", "js_library", "AngularJS"),
        (r"bootstrap(?:\.bundle)?(?:\.min)?\.js", "js_library", "Bootstrap"),
        (r"cdn\.tailwindcss\.com", "framework", "Tailwind CSS"),
        (r"/wp-content/themes/", "cms", "WordPress"),
        (r"/wp-includes/", "cms", "WordPress"),
        (r"wp-json", "cms", "WordPress"),
        (r"/sites/default/files/", "cms", "Drupal"),
    ]

    @classmethod
    def detect(cls, headers: dict, html_content: str = "", cookies: dict = None) -> list[dict]:
        """Detect technologies from headers, HTML, and cookies.
        
        Returns list of dicts:
        [{
            "category": "server|framework|language|cms|js_library|cdn",
            "name": "...",
            "version": "..." or None,
            "confidence": "HIGH|MEDIUM|LOW",
            "evidence": "..."
        }]
        """
        detected: dict[tuple[str, str], dict] = {}

        def record(category: str, name: str, version: str | None, confidence: str, evidence: str):
            key = (category, name)
            # Upgrade confidence if already found
            if key in detected:
                current = detected[key]
                if version and not current["version"]:
                    current["version"] = version
                if confidence == "HIGH":
                    current["confidence"] = "HIGH"
                current["evidence"] += f"; {evidence}"
            else:
                detected[key] = {
                    "category": category,
                    "name": name,
                    "version": version.strip() if version else None,
                    "confidence": confidence,
                    "evidence": evidence,
                }

        # 1. Inspect HTTP Headers
        normalized_headers = {k.lower(): str(v) for k, v in headers.items()}

        for header_key, pattern, cat, tech_name in cls.HEADER_SIGNATURES:
            if header_key in normalized_headers:
                val = normalized_headers[header_key]
                match = re.search(pattern, val, re.IGNORECASE)
                if match:
                    version = match.group(1) if match.groups() and match.group(1) else None
                    confidence = "HIGH" if version or "server" in header_key or "powered" in header_key else "MEDIUM"
                    record(cat, tech_name, version, confidence, f"Header '{header_key}': '{val}'")

        # 2. Inspect Cookies
        if cookies:
            for cookie_name in cookies.keys():
                c_clean = cookie_name.lower().strip()
                for sig, (cat, tech_name, conf) in cls.COOKIE_SIGNATURES.items():
                    if sig in c_clean:
                        record(cat, tech_name, None, conf, f"Cookie present: '{cookie_name}'")

        # 3. Inspect HTML Content (Meta tags, scripts, comments)
        if html_content:
            try:
                soup = BeautifulSoup(html_content[:500000], "html.parser")
            except Exception:
                soup = None

            if soup:
                # Meta generator tag
                for meta in soup.find_all("meta", attrs={"name": re.compile(r"^generator$", re.I)}):
                    content = meta.get("content", "").strip()
                    if content:
                        # Extract generator and potential version
                        gen_match = re.search(r"^([A-Za-z0-9_\-\.\s]+?)(?:\s+([\d.]+))?$", content)
                        if gen_match:
                            name = gen_match.group(1).strip()
                            ver = gen_match.group(2) if gen_match.group(2) else None
                            cat = "cms" if any(w in name.lower() for w in ["wordpress", "drupal", "joomla", "ghost"]) else "framework"
                            record(cat, name, ver, "HIGH", f"Meta generator: '{content}'")

                # Script src attributes
                for script in soup.find_all("script", src=True):
                    src = script["src"]
                    for pattern, cat, tech_name in cls.SCRIPT_SIGNATURES:
                        m = re.search(pattern, src, re.IGNORECASE)
                        if m:
                            ver = m.group(1) if m.groups() and m.group(1) else None
                            record(cat, tech_name, ver, "HIGH", f"Script src: '{src}'")

                # Body text / links signatures
                for pattern, cat, tech_name in cls.SCRIPT_SIGNATURES:
                    if pattern in html_content:
                        record(cat, tech_name, None, "MEDIUM", f"HTML signature match: '{pattern}'")

        # Return sorted list of detections
        return list(detected.values())
