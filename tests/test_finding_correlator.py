from unittest.mock import MagicMock
from app.security.finding_correlator import FindingCorrelator


def test_correlate_xss_and_missing_csp():
    """Verify Reflected XSS and Missing CSP are correlated as a synergistic attack vector."""
    v1 = MagicMock()
    v1.id = 101
    v1.title = "Reflected Cross-Site Scripting (XSS)"
    v1.affected_url = "https://target.test/search?q=test"

    v2 = MagicMock()
    v2.id = 102
    v2.title = "Missing Defensive Header: Content-Security-Policy"
    v2.affected_url = "https://target.test/"

    correlations = FindingCorrelator.correlate_target_findings([v1, v2], target_id=1)
    assert len(correlations) >= 1
    corr = next(c for c in correlations if c["correlation_type"] == "synergistic_vector")
    assert corr["source_finding_id"] == 101
    assert corr["target_finding_id"] == 102
    assert "Content-Security-Policy" in corr["explanation"]


def test_correlate_diagnostic_stack_trace_and_server_banner():
    """Verify Stack Trace and Server Banner are correlated as diagnostic exposure synergy."""
    v1 = MagicMock()
    v1.id = 201
    v1.title = "Detailed Technical Error / Stack Trace (Python Stack Trace)"
    v1.affected_url = "https://target.test/api/err"

    v2 = MagicMock()
    v2.id = 202
    v2.title = "Server Software Version Disclosure"
    v2.affected_url = "https://target.test/"

    correlations = FindingCorrelator.correlate_target_findings([v1, v2], target_id=1)
    corr = next(c for c in correlations if c["correlation_type"] == "diagnostic_exposure")
    assert "Information Leakage Synergy" in corr["explanation"]


def test_correlate_co_located_endpoint():
    """Verify multiple distinct vulnerabilities on the same URL are flagged as endpoint concentration."""
    v1 = MagicMock()
    v1.id = 301
    v1.title = "SQL Injection"
    v1.affected_url = "https://target.test/profile?id=5"

    v2 = MagicMock()
    v2.id = 302
    v2.title = "Reflected Cross-Site Scripting"
    v2.affected_url = "https://target.test/profile?id=5"

    correlations = FindingCorrelator.correlate_target_findings([v1, v2], target_id=1)
    corr = next(c for c in correlations if c["correlation_type"] == "co_located_endpoint")
    assert "Concentrated Attack Surface" in corr["explanation"]


def test_correlate_repeated_flaws_across_endpoints():
    """Verify identical flaw across different URLs is flagged as a systemic issue."""
    v1 = MagicMock()
    v1.id = 401
    v1.title = "Missing Defensive Header: Content-Security-Policy"
    v1.affected_url = "https://target.test/home"

    v2 = MagicMock()
    v2.id = 402
    v2.title = "Missing Defensive Header: Content-Security-Policy"
    v2.affected_url = "https://target.test/about"

    correlations = FindingCorrelator.correlate_target_findings([v1, v2], target_id=1)
    corr = next(c for c in correlations if c["correlation_type"] == "repeated_flaw")
    assert "Systemic Pattern" in corr["explanation"]


def test_correlate_no_duplicates():
    """Ensure duplicate pairs (A-B and B-A) are prevented."""
    v1 = MagicMock()
    v1.id = 501
    v1.title = "Reflected Cross-Site Scripting (XSS)"
    v1.affected_url = "https://target.test/page"

    v2 = MagicMock()
    v2.id = 502
    v2.title = "Missing Defensive Header: Content-Security-Policy"
    v2.affected_url = "https://target.test/page"

    correlations = FindingCorrelator.correlate_target_findings([v1, v2], target_id=1)
    # Check that pair (501, 502) is only recorded once
    pairs = [tuple(sorted([c["source_finding_id"], c["target_finding_id"]])) for c in correlations]
    assert len(pairs) == len(set(pairs))
