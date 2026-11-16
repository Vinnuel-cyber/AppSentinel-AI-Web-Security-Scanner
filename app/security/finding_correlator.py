from urllib.parse import urlparse
from collections import defaultdict


class FindingCorrelator:
    """Enterprise Finding Correlation & Compound Risk Analyzer.
    
    Identifies synergistic weaknesses and systemic exposure patterns:
    - Synergistic Vector: Missing CSP combined with Reflected XSS.
    - Diagnostic Exposure: Runtime stack traces combined with server software banner disclosure.
    - Endpoint Concentration: Multiple independent flaws co-located on the same URL path.
    - Systemic Flaw: Repeated vulnerability occurrences across disparate application endpoints.
    
    Preserves finding integrity: Never collapses or mutates independent findings.
    """

    @classmethod
    def correlate_target_findings(cls, vulnerabilities: list, target_id: int) -> list[dict]:
        """Analyze a list of Vulnerability instances for a target and return correlation records."""
        correlations = []
        seen_pairs = set()

        if not vulnerabilities or len(vulnerabilities) < 2:
            return correlations

        # Index vulnerabilities by type, URL, and parameter
        by_endpoint = defaultdict(list)
        by_title = defaultdict(list)
        xss_findings = []
        csp_findings = []
        trace_findings = []
        banner_findings = []

        for v in vulnerabilities:
            # Group by normalized path
            parsed = urlparse(v.affected_url)
            norm_path = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            by_endpoint[norm_path].append(v)
            by_title[v.title.lower()].append(v)

            title_l = v.title.lower()
            if "cross-site scripting" in title_l or "xss" in title_l:
                xss_findings.append(v)
            if "content-security-policy" in title_l or "csp" in title_l:
                csp_findings.append(v)
            if "stack trace" in title_l or "technical error" in title_l:
                trace_findings.append(v)
            if "server software version" in title_l or "x-powered-by" in title_l:
                banner_findings.append(v)

        # 1. Synergistic Attack Vector: Reflected XSS + Missing CSP
        for xss_v in xss_findings:
            for csp_v in csp_findings:
                pair_key = tuple(sorted([xss_v.id, csp_v.id]))
                if pair_key not in seen_pairs:
                    seen_pairs.add(pair_key)
                    correlations.append({
                        "target_id": target_id,
                        "source_finding_id": xss_v.id,
                        "target_finding_id": csp_v.id,
                        "correlation_type": "synergistic_vector",
                        "explanation": (
                            f"Compound Risk: Reflected XSS on '{xss_v.affected_url}' is compounded by the absence "
                            "of an enforcing Content-Security-Policy (CSP). Without CSP script-src restrictions, "
                            "injected client scripts will execute unconstrained in modern user browsers."
                        ),
                    })

        # 2. Diagnostic Exposure: Stack Trace + Server Banner Disclosure
        for tr_v in trace_findings:
            for ban_v in banner_findings:
                pair_key = tuple(sorted([tr_v.id, ban_v.id]))
                if pair_key not in seen_pairs:
                    seen_pairs.add(pair_key)
                    correlations.append({
                        "target_id": target_id,
                        "source_finding_id": tr_v.id,
                        "target_finding_id": ban_v.id,
                        "correlation_type": "diagnostic_exposure",
                        "explanation": (
                            f"Information Leakage Synergy: Detailed technical error traces on '{tr_v.affected_url}' "
                            f"combine with software version disclosure ('{ban_v.title}') to provide an attacker with "
                            "comprehensive intelligence regarding exact backend framework versions and internal filesystem layout."
                        ),
                    })

        # 3. Endpoint Concentration: Multiple findings on identical URL
        for path, endpoint_vulns in by_endpoint.items():
            if len(endpoint_vulns) >= 2:
                for i in range(len(endpoint_vulns)):
                    for j in range(i + 1, len(endpoint_vulns)):
                        v1 = endpoint_vulns[i]
                        v2 = endpoint_vulns[j]
                        pair_key = tuple(sorted([v1.id, v2.id]))
                        if pair_key not in seen_pairs:
                            seen_pairs.add(pair_key)
                            correlations.append({
                                "target_id": target_id,
                                "source_finding_id": v1.id,
                                "target_finding_id": v2.id,
                                "correlation_type": "co_located_endpoint",
                                "explanation": (
                                    f"Concentrated Attack Surface: Multiple security weaknesses ('{v1.title}' and '{v2.title}') "
                                    f"co-exist on the same endpoint ('{path}'), indicating an unhardened controller or handler."
                                ),
                            })

        # 4. Systemic Flaw: Same vulnerability type across multiple endpoints
        for title_key, title_vulns in by_title.items():
            if len(title_vulns) >= 2:
                primary = title_vulns[0]
                for other in title_vulns[1:]:
                    pair_key = tuple(sorted([primary.id, other.id]))
                    if pair_key not in seen_pairs:
                        seen_pairs.add(pair_key)
                        correlations.append({
                            "target_id": target_id,
                            "source_finding_id": primary.id,
                            "target_finding_id": other.id,
                            "correlation_type": "repeated_flaw",
                            "explanation": (
                                f"Systemic Pattern: '{primary.title}' recurred across multiple application routes "
                                f"('{primary.affected_url}' and '{other.affected_url}'), suggesting a missing global middleware "
                                "or shared configuration template flaw rather than an isolated bug."
                            ),
                        })

        return correlations
