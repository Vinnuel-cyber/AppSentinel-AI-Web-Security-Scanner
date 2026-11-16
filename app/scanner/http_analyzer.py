from urllib.parse import urlparse
import requests


class HTTPAnalyzer:
    """Enterprise HTTP Response and Protocol Inspector.
    
    Extracts and audits:
    - Normalized response headers
    - Cookie security flags (HttpOnly, Secure, SameSite) without leaking sensitive values
    - Cache policy evaluation (Cache-Control, Pragma, ETag, Expires)
    - Redirect chain path and domain scope
    """

    @classmethod
    def analyze_response(cls, response: requests.Response, authorized_domain: str) -> dict:
        """Comprehensive audit of an HTTP response."""
        normalized_headers = {k.title(): v for k, v in response.headers.items()}
        
        # 1. Content details
        content_type = response.headers.get("Content-Type", "")
        content_length = len(response.content) if response.content else 0
        server = response.headers.get("Server", "Unknown")

        # 2. Redirect chain analysis
        redirect_chain = []
        is_cross_domain_redirect = False
        
        for hop in response.history:
            hop_parsed = urlparse(hop.url)
            hop_domain = hop_parsed.hostname.lower() if hop_parsed.hostname else ""
            if hop_domain and hop_domain != authorized_domain.lower() and not hop_domain.endswith("." + authorized_domain.lower()):
                is_cross_domain_redirect = True

            redirect_chain.append({
                "from_url": hop.url,
                "status_code": hop.status_code,
                "domain": hop_domain,
                "location": hop.headers.get("Location", ""),
            })

        final_parsed = urlparse(response.url)
        final_domain = final_parsed.hostname.lower() if final_parsed.hostname else ""
        if final_domain and final_domain != authorized_domain.lower() and not final_domain.endswith("." + authorized_domain.lower()):
            is_cross_domain_redirect = True

        # 3. Cookie security flags analysis (Strict privacy: never record values!)
        cookie_audits = []
        for cookie in response.cookies:
            has_httponly = bool(cookie.has_nonstandard_attr("httponly") or cookie.has_nonstandard_attr("HttpOnly"))
            has_secure = bool(cookie.secure)
            samesite = cookie.get_nonstandard_attr("samesite") or cookie.get_nonstandard_attr("SameSite") or "None"

            issues = []
            if not has_httponly:
                issues.append("Missing HttpOnly flag (accessible to JavaScript / XSS)")
            if not has_secure and response.url.startswith("https://"):
                issues.append("Missing Secure flag on HTTPS connection")
            if samesite.lower() not in ("strict", "lax"):
                issues.append(f"Suboptimal SameSite policy ('{samesite}')")

            cookie_audits.append({
                "name": cookie.name,
                "domain": cookie.domain,
                "path": cookie.path,
                "secure": has_secure,
                "httponly": has_httponly,
                "samesite": samesite,
                "issues": issues,
                "is_secure_config": len(issues) == 0,
            })

        # 4. Cache control evaluation
        cache_control = response.headers.get("Cache-Control", "")
        pragma = response.headers.get("Pragma", "")
        expires = response.headers.get("Expires", "")
        etag = response.headers.get("ETag", "")

        cache_analysis = {
            "cache_control": cache_control,
            "pragma": pragma,
            "expires": expires,
            "etag": bool(etag),
            "is_public_cached": "public" in cache_control.lower(),
            "is_no_store": "no-store" in cache_control.lower(),
            "is_no_cache": "no-cache" in cache_control.lower(),
        }

        return {
            "status_code": response.status_code,
            "final_url": response.url,
            "content_type": content_type,
            "content_length": content_length,
            "server": server,
            "redirect_count": len(redirect_chain),
            "redirect_chain": redirect_chain,
            "is_cross_domain_redirect": is_cross_domain_redirect,
            "cookies": cookie_audits,
            "cache_policy": cache_analysis,
            "headers": normalized_headers,
        }
