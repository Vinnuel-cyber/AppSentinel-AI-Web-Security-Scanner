import socket


class DNSAnalyzer:
    """Enterprise Public DNS Enumeration and Analysis Engine.
    
    Collects standard DNS resource records:
    - A: IPv4 host address
    - AAAA: IPv6 host address
    - MX: Mail exchanger
    - NS: Authoritative name servers
    - TXT: Verification and SPF/DKIM records
    - CNAME: Canonical aliases
    """

    SUPPORTED_RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]
    DEFAULT_TIMEOUT = 4.0

    @classmethod
    def resolve_records(cls, domain: str, timeout: float = DEFAULT_TIMEOUT) -> list[dict]:
        """Query DNS records using dnspython with socket fallback."""
        records = []
        domain_clean = domain.strip().lower()

        try:
            import dns.resolver
            import dns.exception

            resolver = dns.resolver.Resolver()
            resolver.timeout = timeout
            resolver.lifetime = timeout

            for rtype in cls.SUPPORTED_RECORD_TYPES:
                try:
                    answers = resolver.resolve(domain_clean, rtype)
                    ttl = answers.rrset.ttl if answers.rrset else None
                    for rdata in answers:
                        val = rdata.to_text().strip('"')
                        records.append({
                            "record_type": rtype,
                            "name": domain_clean,
                            "value": val,
                            "ttl": ttl,
                        })
                except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
                    continue
                except dns.exception.Timeout:
                    continue
                except Exception:
                    continue

        except ImportError:
            # Fallback to standard socket library for A records
            try:
                addr_info = socket.getaddrinfo(domain_clean, None, proto=socket.IPPROTO_TCP)
                seen_ips = set()
                for family, _, _, _, sockaddr in addr_info:
                    ip = sockaddr[0]
                    if ip not in seen_ips:
                        seen_ips.add(ip)
                        rtype = "AAAA" if ":" in ip else "A"
                        records.append({
                            "record_type": rtype,
                            "name": domain_clean,
                            "value": ip,
                            "ttl": None,
                        })
            except Exception:
                pass

        return records
