from datetime import datetime, timezone
import time
from app.models import (
    db,
    Target,
    ReconScan,
    DiscoveredEndpoint,
    TechnologyFingerprint,
    DNSRecord,
    SecurityHeaderFinding,
    WebsiteMetadata,
)
from app.scanner import (
    AvailabilityChecker,
    TechnologyDetector,
    HTTPAnalyzer,
    SecurityHeadersAnalyzer,
    EndpointDiscoveryEngine,
    DNSAnalyzer,
    MetadataAnalyzer,
)
from app.security.target_validator import TargetValidator, TargetValidationError


class ReconAuthorizationError(Exception):
    """Raised when target does not meet authorization or verification requirements."""
    pass


class ReconManager:
    """Enterprise Reconnaissance Orchestration Service."""

    @classmethod
    def validate_target_for_recon(cls, target: Target, user, allow_private: bool = False) -> None:
        """Enforce strict authorization and verification policies prior to scan execution."""
        if not target:
            raise ReconAuthorizationError("Target not found.")

        # Soft deletion check
        if not target.is_active or target.deleted_at is not None:
            raise ReconAuthorizationError("Target has been deleted or deactivated.")

        # User ownership / RBAC check
        if getattr(user, "role", None) != "ADMIN" and target.owner_id != user.id:
            raise ReconAuthorizationError("Unauthorized: You do not own this target.")

        # Verification check
        if not target.is_verified or target.verification_status != "VERIFIED":
            raise ReconAuthorizationError(
                f"Target ownership is not verified (status: {target.verification_status}). "
                "Reconnaissance operations are strictly prohibited on unverified targets."
            )

        # SSRF revalidation check
        try:
            TargetValidator.validate_target_url(target.target_url, allow_private=allow_private)
        except TargetValidationError as err:
            raise ReconAuthorizationError(f"Target URL failed destination security validation: {err}")

    @classmethod
    def run_recon_scan(
        cls,
        scan_id: int,
        allow_private: bool = False,
        timeout: float = 8.0,
    ) -> ReconScan:
        """Execute complete passive reconnaissance pipeline for a registered ReconScan."""
        scan = db.session.get(ReconScan, scan_id)
        if not scan:
            raise ValueError(f"ReconScan with id {scan_id} does not exist.")

        target = db.session.get(Target, scan.target_id)
        if not target:
            scan.status = "failed"
            scan.error_message = "Target not found."
            scan.completed_at = datetime.now(timezone.utc)
            db.session.commit()
            return scan

        # Mark as running
        scan.status = "running"
        scan.started_at = datetime.now(timezone.utc)
        db.session.commit()

        start_time = time.perf_counter()

        try:
            domain = target.domain or TargetValidator.extract_domain(target.target_url)

            # 1. Availability Check
            avail_res = AvailabilityChecker.check_availability(
                target.target_url,
                timeout=timeout,
                allow_private=allow_private,
            )
            scan.availability_status = avail_res.get("status", "UNKNOWN")
            scan.http_status = avail_res.get("http_status")
            scan.response_time_ms = avail_res.get("response_time_ms", 0)
            scan.final_url = avail_res.get("final_url", target.target_url)
            scan.ip_address = avail_res.get("ip_address")

            raw_resp = avail_res.get("raw_response")
            html_content = raw_resp.text if raw_resp is not None else ""
            response_headers = raw_resp.headers if raw_resp is not None else {}
            response_cookies = raw_resp.cookies.get_dict() if raw_resp is not None else {}

            db.session.flush()

            # Check if scan was cancelled while running
            current_status = db.session.scalar(db.select(ReconScan.status).filter_by(id=scan.id))
            if current_status == "cancelled":
                scan.status = "cancelled"
                return scan

            # 2. DNS Enumeration
            dns_records = DNSAnalyzer.resolve_records(domain, timeout=timeout / 2)
            for rec in dns_records:
                dns_entry = DNSRecord(
                    scan_id=scan.id,
                    record_type=rec["record_type"],
                    name=rec["name"],
                    value=rec["value"],
                    ttl=rec.get("ttl"),
                )
                db.session.add(dns_entry)

            db.session.flush()

            # Check for cancellation
            current_status = db.session.scalar(db.select(ReconScan.status).filter_by(id=scan.id))
            if current_status == "cancelled":
                scan.status = "cancelled"
                return scan

            # 3. Security Headers Analysis
            is_https = (scan.final_url or target.target_url).lower().startswith("https://")
            header_findings = SecurityHeadersAnalyzer.evaluate(response_headers, is_https=is_https)
            missing_headers_count = 0
            for h in header_findings:
                if not h["present"] or h["status"] == "SUBOPTIMAL":
                    missing_headers_count += 1
                finding_entry = SecurityHeaderFinding(
                    scan_id=scan.id,
                    header_name=h["header_name"],
                    present=h["present"],
                    value=h["value"],
                    status=h["status"],
                    risk_level=h["risk_level"],
                    remediation=h["remediation"],
                )
                db.session.add(finding_entry)
            scan.total_security_headers_missing = missing_headers_count

            # 4. Passive Technology Fingerprinting
            technologies = TechnologyDetector.detect(
                response_headers,
                html_content=html_content,
                cookies=response_cookies,
            )
            for tech in technologies:
                tech_entry = TechnologyFingerprint(
                    scan_id=scan.id,
                    category=tech["category"],
                    name=tech["name"],
                    version=tech.get("version"),
                    confidence=tech.get("confidence", "MEDIUM"),
                    evidence=tech.get("evidence"),
                )
                db.session.add(tech_entry)
            scan.total_technologies = len(technologies)

            # 5. Metadata and OpenGraph
            meta_data = MetadataAnalyzer.extract_metadata(html_content, fallback_url=target.target_url)
            metadata_record = WebsiteMetadata(
                scan_id=scan.id,
                title=meta_data.get("title"),
                description=meta_data.get("description"),
                generator=meta_data.get("generator"),
                canonical_url=meta_data.get("canonical_url"),
                language=meta_data.get("language"),
            )
            metadata_record.set_open_graph(meta_data.get("open_graph", {}))
            db.session.add(metadata_record)

            # 6. Endpoint Discovery (Safe passive crawl)
            endpoints = EndpointDiscoveryEngine.discover_all(
                base_url=scan.final_url or target.target_url,
                authorized_domain=domain,
                html_content=html_content,
                timeout=timeout / 2,
                allow_private=allow_private,
            )
            for ep in endpoints:
                ep_entry = DiscoveredEndpoint(
                    scan_id=scan.id,
                    url=ep["url"],
                    http_method=ep.get("http_method", "GET"),
                    status_code=ep.get("status_code"),
                    content_type=ep.get("content_type"),
                    source=ep.get("source", "html_link"),
                )
                db.session.add(ep_entry)
            scan.total_endpoints = len(endpoints)

            # Finalize scan status
            elapsed = time.perf_counter() - start_time
            scan.duration_seconds = round(elapsed, 2)
            scan.completed_at = datetime.now(timezone.utc)
            scan.status = "completed"
            db.session.commit()
            return scan

        except Exception as exc:
            db.session.rollback()
            # Reload scan to save failure state
            scan = db.session.get(ReconScan, scan_id)
            if scan:
                elapsed = time.perf_counter() - start_time
                scan.duration_seconds = round(elapsed, 2)
                scan.completed_at = datetime.now(timezone.utc)
                scan.status = "failed"
                scan.error_message = str(exc)
                db.session.commit()
            raise
