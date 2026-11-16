from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

from .user import User
from .target import Target
from .scan import Scan, ScanURL, ScanLog, ScanSetting
from .vulnerability import Vulnerability, VulnerabilityEvidence, AIAnalysis, Report

__all__ = [
    "db",
    "User",
    "Target",
    "Scan",
    "ScanURL",
    "ScanLog",
    "ScanSetting",
    "Vulnerability",
    "VulnerabilityEvidence",
    "AIAnalysis",
    "Report",
]
