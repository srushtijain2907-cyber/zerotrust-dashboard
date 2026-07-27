"""
config.py
All threshold values sourced from IEEE research papers.
Jeong & Yang (2025) Applied Sciences 15(17):9551 — Trust Score thresholds
Al-Shehari et al. (2023) IEEE Access 11:118170 — Isolation Forest parameters
NIST SP 800-207 — Zero Trust decision framework
"""

# ─── Zero Trust Decision Thresholds ──────────────────────────────────────────
# Source: Jeong & Yang (2025), Section 4.1, Page 14
# "Allow access if TS ≥ 80, MFA if 60–79, Block if < 60"
# Normalized to 0.00–1.00 scale (divide by 100)
THRESHOLD_ALLOW        = 0.80   # TS ≥ 0.80 → ALLOW
THRESHOLD_MFA          = 0.60   # 0.60 ≤ TS < 0.80 → MFA REQUIRED
THRESHOLD_BLOCK        = 0.30   # 0.30 ≤ TS < 0.60 → BLOCK
# < 0.30 → CRITICAL BLOCK (extension of Jeong & Yang 3-tier model)

# ─── Trust Score Factor Weights ──────────────────────────────────────────────
# Source: Jeong & Yang (2025), Section 3.2.2, Page 10-11
# "wB=0.4, wN=0.3, wD=0.2, wT=0.1 — justified by Verizon DBIR 2023:
#  >70% of security incidents involved the human element"
WEIGHT_USER_BEHAVIOR   = 0.40   # B — most dynamic, highest risk indicator
WEIGHT_NETWORK         = 0.30   # N — network environment trustworthiness
WEIGHT_DEVICE          = 0.20   # D — device security posture
WEIGHT_THREAT_HISTORY  = 0.10   # T — historical threat record

# ─── Isolation Forest Parameters ─────────────────────────────────────────────
# Source: Al-Shehari et al. (2023), IEEE Access, Section IV-B, Table 6
# "Best detection results: contamination=0.02, accuracy=98%, F-score=99%"
IF_CONTAMINATION       = 0.02
IF_N_ESTIMATORS        = 100
IF_RANDOM_STATE        = 42

# ─── Off-Hours Definition ────────────────────────────────────────────────────
# Source: Jeong & Yang (2025), Table 2, Row ③ "Off-Hours Login"
# "02:00–05:00 → score=0 (very high risk time logins)"
ODD_HOUR_START         = 2      # 2 AM
ODD_HOUR_END           = 5      # 5 AM

# ─── Action Risk Scores (per AWS CloudTrail event) ───────────────────────────
# These are feature engineering values for the ML model input.
# Higher = more sensitive action. Based on AWS IAM sensitivity classification.
ACTION_RISK_SCORES = {
    # Critical — privilege escalation / identity tampering
    "CreateUser":              9,
    "AttachUserPolicy":        9,
    "PutUserPolicy":           9,
    "CreateAccessKey":         9,
    "UpdateLoginProfile":      9,
    "AttachRolePolicy":        8,
    "CreateRole":              8,
    "AssumeRole":              8,
    "DeleteUser":              8,
    "DetachUserPolicy":        7,
    # High — data destruction / exposure
    "DeleteBucket":            9,
    "PutBucketPolicy":         8,
    "DeleteObject":            7,
    "PutBucketAcl":            7,
    "GetObject":               5,
    "PutObject":               4,
    "ListBuckets":             2,
    # Medium — compute / network changes
    "RunInstances":            6,
    "TerminateInstances":      7,
    "StopInstances":           6,
    "AuthorizeSecurityGroup":  7,
    "RevokeSecurityGroup":     5,
    "CreateVpc":               5,
    # Low — read-only / informational
    "DescribeInstances":       2,
    "ListUsers":               2,
    "GetCallerIdentity":       1,
    "ListAccessKeys":          4,
    "ConsoleLogin":            3,
    "ConsoleLoginFailure":     8,
}

# ─── High-Risk Countries (ISO 2-letter codes) ────────────────────────────────
# Based on common threat intelligence feeds (CISA advisories)
HIGH_RISK_COUNTRIES = {
    "CN", "RU", "KP", "IR", "SY", "CU"
}

# ─── Cloud Configuration ─────────────────────────────────────────────────────
# AWS — uses boto3, reads from ~/.aws/credentials automatically
# No hardcoded keys. User sets up credentials once via `aws configure`.
AWS_REGION             = "ap-south-1"
AWS_LOG_HOURS_BACK     = 24     # How many hours of CloudTrail logs to fetch

# Azure — uses DefaultAzureCredential (env vars or az login)
# No hardcoded keys. User runs `az login` once.
AZURE_RESOURCE_GROUP   = "zero-trust-rg"

# GCP — uses Application Default Credentials (gcloud auth application-default login)
# No hardcoded keys.
GCP_PROJECT_ID         = None   # Auto-detected from environment

# ─── Dashboard ───────────────────────────────────────────────────────────────
DASHBOARD_PORT         = 5000
DASHBOARD_HOST         = "0.0.0.0"
SECRET_KEY             = "zerotrust-2026-ghrce-change-in-prod"
LOG_REFRESH_SECONDS    = 30     # How often dashboard auto-refreshes
