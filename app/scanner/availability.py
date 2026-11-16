import time
import requests
from requests.exceptions import Timeout, SSLError, ConnectionError, RequestException
from app.security.target_validator import TargetValidator, TargetValidationError


class AvailabilityChecker:
    """Enterprise Website Availability Engine.
    
    Classifies availability status into:
    - ONLINE: Host reachable and returns valid HTTP status (2xx, 3xx, 4xx non-blocked)
    - OFFLINE: Host unreachable or connection refused
    - TIMEOUT: Connection or read timed out within configured threshold
    - SSL_ERROR: TLS/SSL handshake failure or certificate validation error
    - BLOCKED: WAF / Access forbidden / Rate limited / Geo-blocked (e.g. 403 with firewall markers or 429)
    - ERROR: Generic unexpected protocol or network error
    """

    DEFAULT_TIMEOUT = 8.0
    DEFAULT_USER_AGENT = "AppSentinel-Recon/2.0 (Security Auditor; +https://appsentinel.local)"

    BLOCKED_STATUS_CODES = {403, 406, 429}
    BLOCKED_SERVER_SIGNATURES = [
        "cloudflare",
        "incapsula",
        "imperva",
        "akamai",
        "mod_security",
        "barracuda",
        "sucuri",
        "fortiweb",
    ]

    @classmethod
    def check_availability(
        cls,
        target_url: str,
        timeout: float = DEFAULT_TIMEOUT,
        verify_ssl: bool = True,
        user_agent: str = DEFAULT_USER_AGENT,
        allow_private: bool = False,
    ) -> dict:
        """Perform comprehensive HTTP/HTTPS availability analysis."""
        # 1. SSRF & Scheme Validation
        try:
            norm_url, domain, resolved_ips = TargetValidator.validate_target_url(
                target_url, allow_private=allow_private
            )
        except TargetValidationError as err:
            return {
                "target_url": target_url,
                "status": "ERROR",
                "is_online": False,
                "http_status": None,
                "response_time_ms": 0,
                "final_url": target_url,
                "redirects": [],
                "server_header": None,
                "ip_address": None,
                "error_message": f"Target validation rejected: {err}",
            }

        primary_ip = resolved_ips[0] if resolved_ips else None
        headers = {
            "User-Agent": user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        }

        session = requests.Session()
        session.max_redirects = 5

        start_time = time.perf_counter()
        redirect_history = []

        try:
            response = session.get(
                norm_url,
                headers=headers,
                timeout=timeout,
                verify=verify_ssl,
                allow_redirects=True,
            )
            elapsed_ms = int((time.perf_counter() - start_time) * 1000)

            # Record redirect hops
            for hop in response.history:
                redirect_history.append({
                    "url": hop.url,
                    "status_code": hop.status_code,
                    "reason": hop.reason,
                })

            final_url = response.url
            server_header = response.headers.get("Server")

            # Check if request was blocked
            is_blocked = False
            if response.status_code in cls.BLOCKED_STATUS_CODES:
                body_lower = response.text[:2048].lower()
                server_lower = (server_header or "").lower()
                for sig in cls.BLOCKED_SERVER_SIGNATURES:
                    if sig in body_lower or sig in server_lower:
                        is_blocked = True
                        break

            if is_blocked:
                status_classification = "BLOCKED"
            elif response.status_code >= 500:
                # 5xx server errors still mean host is online (server replied)
                status_classification = "ONLINE"
            elif response.status_code in (401, 403, 404):
                status_classification = "ONLINE"
            else:
                status_classification = "ONLINE"

            return {
                "target_url": target_url,
                "status": status_classification,
                "is_online": True,
                "http_status": response.status_code,
                "response_time_ms": elapsed_ms,
                "final_url": final_url,
                "redirects": redirect_history,
                "server_header": server_header,
                "ip_address": primary_ip,
                "content_type": response.headers.get("Content-Type", ""),
                "content_length": len(response.content),
                "error_message": None,
                "raw_response": response,
            }

        except SSLError as err:
            elapsed_ms = int((time.perf_counter() - start_time) * 1000)
            return {
                "target_url": target_url,
                "status": "SSL_ERROR",
                "is_online": False,
                "http_status": None,
                "response_time_ms": elapsed_ms,
                "final_url": target_url,
                "redirects": redirect_history,
                "server_header": None,
                "ip_address": primary_ip,
                "error_message": f"SSL/TLS Handshake failure: {err}",
                "raw_response": None,
            }
        except Timeout as err:
            elapsed_ms = int((time.perf_counter() - start_time) * 1000)
            return {
                "target_url": target_url,
                "status": "TIMEOUT",
                "is_online": False,
                "http_status": None,
                "response_time_ms": elapsed_ms,
                "final_url": target_url,
                "redirects": redirect_history,
                "server_header": None,
                "ip_address": primary_ip,
                "error_message": f"Connection timed out after {timeout} seconds: {err}",
                "raw_response": None,
            }
        except ConnectionError as err:
            elapsed_ms = int((time.perf_counter() - start_time) * 1000)
            return {
                "target_url": target_url,
                "status": "OFFLINE",
                "is_online": False,
                "http_status": None,
                "response_time_ms": elapsed_ms,
                "final_url": target_url,
                "redirects": redirect_history,
                "server_header": None,
                "ip_address": primary_ip,
                "error_message": f"Host unreachable or connection refused: {err}",
                "raw_response": None,
            }
        except RequestException as err:
            elapsed_ms = int((time.perf_counter() - start_time) * 1000)
            return {
                "target_url": target_url,
                "status": "ERROR",
                "is_online": False,
                "http_status": None,
                "response_time_ms": elapsed_ms,
                "final_url": target_url,
                "redirects": redirect_history,
                "server_header": None,
                "ip_address": primary_ip,
                "error_message": f"HTTP request error: {err}",
                "raw_response": None,
            }
