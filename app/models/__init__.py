from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

from .user import User
from .target import Target, TargetAuditLog
from .scan import Scan, ScanURL, ScanLog, ScanSetting
from .vulnerability import Vulnerability, VulnerabilityEvidence, AIAnalysis, Report
from .recon import (
    ReconScan,
    DiscoveredEndpoint,
    TechnologyFingerprint,
    DNSRecord,
    SecurityHeaderFinding,
    WebsiteMetadata,
)
from .owasp import (
    OWASPAssessment,
    OWASPFindingMapping,
    RiskAssessment,
    FindingCorrelation,
    RemediationRecommendation,
)
from .ai import AIConversation, AIMessage, AIUsageLog

__all__ = [
    "db",
    "User",
    "Target",
    "TargetAuditLog",
    "Scan",
    "ScanURL",
    "ScanLog",
    "ScanSetting",
    "Vulnerability",
    "VulnerabilityEvidence",
    "AIAnalysis",
    "AIConversation",
    "AIMessage",
    "AIUsageLog",
    "Report",
    "ReconScan",
    "DiscoveredEndpoint",
    "TechnologyFingerprint",
    "DNSRecord",
    "SecurityHeaderFinding",
    "WebsiteMetadata",
    "OWASPAssessment",
    "OWASPFindingMapping",
    "RiskAssessment",
    "FindingCorrelation",
    "RemediationRecommendation",
]
