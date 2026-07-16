"""Module Cloud — scanners cloud sans SDK avec graceful degradation.

Fonctionnalités :
- S3 Bucket Scanner : vérification HTTP HEAD des buckets AWS S3
- IAM Policy Analyzer : analyse de politiques IAM (wildcards, admin, conditions)
- Cloud Recon (DNS-based) : découverte de ressources cloud via DNS/CNAME

Tous les scanners fonctionnent sans SDK (HTTP + DNS uniquement).
"""

from .scanner import (
    BaseCloudScanner,
    CloudFinding,
    CloudReconResult,
    CloudScanner,
    IAMRisk,
    analyze_iam_policy,
    discover_cloud_resources,
    scan_s3_buckets,
)

__all__ = [
    "BaseCloudScanner",
    "CloudFinding",
    "CloudReconResult",
    "CloudScanner",
    "IAMRisk",
    "analyze_iam_policy",
    "discover_cloud_resources",
    "scan_s3_buckets",
]
