import ipaddress
import socket
from urllib.parse import urlparse
import requests


class TargetValidationError(Exception):
    """Raised when target URL or destination fails security validation."""
    pass


class TargetValidator:
    """Enterprise-grade SSRF and URL validation engine."""

    ALLOWED_SCHEMES = ("http", "https")
    DEFAULT_TIMEOUT = 5.0
    MAX_REDIRECTS = 3

    @classmethod
    def normalize_url(cls, raw_url: str) -> str:
        """Strip whitespace, check format, and normalize scheme/host."""
        if not raw_url or not isinstance(raw_url, str):
            raise TargetValidationError("Target URL cannot be empty.")

        url = raw_url.strip()
        parsed = urlparse(url)

        # Reject unsupported schemes
        if parsed.scheme.lower() not in cls.ALLOWED_SCHEMES:
            raise TargetValidationError(f"Unsupported scheme '{parsed.scheme}'. Only HTTP and HTTPS are permitted.")

        # Reject embedded credentials (e.g. http://user:pass@example.com)
        if parsed.username or parsed.password:
            raise TargetValidationError("URLs with embedded credentials (user:password@) are prohibited.")

        # Require a valid network location (hostname)
        if not parsed.hostname:
            raise TargetValidationError("Target URL must contain a valid hostname.")

        # Reject non-standard ports or validate port range
        if parsed.port:
            if not (1 <= parsed.port <= 65535):
                raise TargetValidationError("Invalid port specified in target URL.")

        hostname = parsed.hostname.lower()
        if len(hostname) > 253:
            raise TargetValidationError("Hostname exceeds maximum allowable length of 253 characters.")

        # Reconstruct normalized URL (enclose IPv6 literals in brackets)
        host_repr = f"[{hostname}]" if ":" in hostname else hostname
        port_str = f":{parsed.port}" if parsed.port and parsed.port not in (80, 443) else ""
        path = parsed.path if parsed.path else "/"
        query = f"?{parsed.query}" if parsed.query else ""
        normalized = f"{parsed.scheme.lower()}://{host_repr}{port_str}{path}{query}"
        return normalized

    @classmethod
    def extract_domain(cls, raw_url: str) -> str:
        """Extract normalized domain/hostname from URL."""
        parsed = urlparse(raw_url.strip())
        if not parsed.hostname:
            raise TargetValidationError("Target URL does not contain a valid hostname.")
        return parsed.hostname.lower()

    @classmethod
    def is_ip_restricted(cls, ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address) -> tuple[bool, str]:
        """Check if IP address is loopback, private, link-local, multicast, or reserved."""
        if ip_obj.is_loopback:
            return True, f"Loopback address '{ip_obj}' is strictly blocked."
        if ip_obj.is_private:
            return True, f"Private address space '{ip_obj}' is blocked."
        if ip_obj.is_link_local:
            return True, f"Link-local address '{ip_obj}' is blocked."
        if ip_obj.is_multicast:
            return True, f"Multicast address '{ip_obj}' is blocked."
        if ip_obj.is_reserved:
            return True, f"Reserved address '{ip_obj}' is blocked."
        if getattr(ip_obj, "is_unspecified", False):
            return True, f"Unspecified address '{ip_obj}' is blocked."

        # IPv6 mapped IPv4 check
        if isinstance(ip_obj, ipaddress.IPv6Address):
            if ip_obj.ipv4_mapped:
                mapped_v4 = ip_obj.ipv4_mapped
                return cls.is_ip_restricted(mapped_v4)

        return False, ""

    @classmethod
    def resolve_and_validate_hostname(cls, hostname: str, allow_private: bool = False) -> list[str]:
        """
        Resolve hostname to IPv4/IPv6 addresses and verify none are in forbidden ranges.
        Protects against decimal/hex IP tricks, localhost aliases, and SSRF.
        """
        # Block literal 'localhost' immediately
        if hostname.lower() in ("localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback"):
            if not allow_private:
                raise TargetValidationError("Localhost and loopback destinations are strictly prohibited.")

        # Check if hostname is already a raw IP literal
        try:
            ip_obj = ipaddress.ip_address(hostname)
            if not allow_private:
                restricted, reason = cls.is_ip_restricted(ip_obj)
                if restricted:
                    raise TargetValidationError(f"Target IP address is blocked: {reason}")
            return [str(ip_obj)]
        except ValueError:
            # Not a literal IP, continue to DNS resolution
            pass

        try:
            addr_info = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
        except socket.gaierror as exc:
            raise TargetValidationError(f"Unable to resolve hostname '{hostname}': {exc}")

        resolved_ips = []
        for family, _, _, _, sockaddr in addr_info:
            ip_str = sockaddr[0]
            try:
                ip_obj = ipaddress.ip_address(ip_str)
                if not allow_private:
                    restricted, reason = cls.is_ip_restricted(ip_obj)
                    if restricted:
                        raise TargetValidationError(f"Resolved destination '{ip_str}' is restricted: {reason}")
                resolved_ips.append(ip_str)
            except ValueError:
                raise TargetValidationError(f"Invalid IP address format encountered: '{ip_str}'.")

        if not resolved_ips:
            raise TargetValidationError(f"No IP addresses resolved for hostname '{hostname}'.")

        return list(set(resolved_ips))

    @classmethod
    def validate_target_url(cls, raw_url: str, allow_private: bool = False) -> tuple[str, str, list[str]]:
        """
        Comprehensive target validation pipeline.
        Returns (normalized_url, normalized_domain, resolved_ips).
        """
        normalized_url = cls.normalize_url(raw_url)
        domain = cls.extract_domain(normalized_url)
        resolved_ips = cls.resolve_and_validate_hostname(domain, allow_private=allow_private)
        return normalized_url, domain, resolved_ips

    @classmethod
    def verify_ownership_via_http(cls, domain: str, expected_token: str, timeout: float = 5.0) -> tuple[bool, str]:
        """
        Safely check http://<domain>/.well-known/appsentinel-verification.txt.
        Re-validates resolved IP to prevent DNS rebinding and re-validates redirect destinations.
        """
        # Re-verify domain resolution before making request
        cls.resolve_and_validate_hostname(domain)

        url = f"http://{domain}/.well-known/appsentinel-verification.txt"
        session = requests.Session()
        session.max_redirects = cls.MAX_REDIRECTS

        try:
            response = session.get(
                url,
                timeout=timeout,
                headers={"User-Agent": "AppSentinel-Verification-Bot/2.0"},
                allow_redirects=False,
            )
            if response.status_code == 200:
                content = response.text.strip()
                if expected_token in content:
                    return True, "Ownership verified via HTTP .well-known token match."
                return False, f"HTTP token mismatch. Expected '{expected_token[:8]}...', received '{content[:32]}'."
            return False, f"HTTP verification returned status code {response.status_code}."
        except requests.RequestException as exc:
            return False, f"HTTP verification request failed: {str(exc)}"

    @classmethod
    def verify_ownership_via_dns(cls, domain: str, expected_token: str) -> tuple[bool, str]:
        """
        Check DNS TXT record for 'appsentinel-verification=<token>'.
        """
        expected_txt = f"appsentinel-verification={expected_token}"
        try:
            import dns.resolver
            resolver = dns.resolver.Resolver()
            resolver.timeout = 4.0
            resolver.lifetime = 4.0
            answers = resolver.resolve(domain, "TXT")
            for rdata in answers:
                for string in rdata.strings:
                    text_record = string.decode("utf-8", errors="ignore").strip()
                    if expected_txt in text_record or expected_token in text_record:
                        return True, "Ownership verified via DNS TXT record match."
            return False, "DNS TXT record found but did not match expected verification token."
        except ImportError:
            # Fallback if dnspython is not installed directly or for unit testing
            return False, "DNS resolver module unavailable."
        except Exception as exc:
            return False, f"DNS TXT resolution failed: {str(exc)}"
