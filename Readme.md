CloudSentinel

CloudSentinel is an on-demand Cloud Security Posture Management (CSPM) tool built to identify common AWS S3 and IAM misconfigurations, calculate a security posture score, and provide clear remediation runbooks.

It is designed as an educational project to demonstrate practical cloud security auditing, data normalization patterns, and object-oriented Python scripting.

🏗️ Pipeline Architecture

   ┌──────────────────────────────┐
   │    cloudscan_orchestrator.py │ <── Pipeline Coordinator
   └──────────────┬───────────────┘
                  │
        ┌─────────┴─────────┐
        ▼                   ▼
┌──────────────┐    ┌──────────────┐
│  S3 Scanner  │    │ IAM Scanner  │
└────────┬──────┘    └──────┬───────┘
         │                  │
         └────────┬─────────┘
                  ▼
┌──────────────────────────────────┐
│       engine/findings.py         │ <── Normalizes raw data to Finding objects
└─────────────────┬────────────────┘
                  ▼
┌──────────────────────────────────┐
│  engine/severity.py & scoring.py │ <── Rule-based severity & scoring calculations
└─────────────────┬────────────────┘
                  ▼
┌──────────────────────────────────┐
│  engine/remediation.py & history.py│ <── Creates fix plans & writes JSON to disk
└─────────────────┬────────────────┘
                  ▼
┌──────────────────────────────────┐
│           dashboard.py           │ <── Visualizes analytics & trends
└──────────────────────────────────┘


🔒 Security Audits & Rules Checked

📦 S3 Storage Configuration Checks

S3_PUBLIC_WRITE_ACCESS (Critical - 20 pts): Flags if a bucket policy allows anonymous write access.

S3_PUBLIC_ACCESS_BLOCK_MISSING (Critical - 20 pts): Flags if S3 Block Public Access is completely disabled.

S3_PUBLIC_READ_ACCESS (High - 15 pts): Flags if a bucket allows open reading via policy or ACL.

S3_ENCRYPTION_DISABLED (High - 15 pts): Checks if default server-side encryption is missing.

S3_VERSIONING_DISABLED (Medium - 10 pts): Flags if versioning is disabled, exposing data to accidental deletion.

S3_LOGGING_DISABLED (Medium - 10 pts): Flags if server access logging is disabled.

👥 IAM Identity Configuration Checks

IAM_MFA_DISABLED_ADMIN_USER (Critical - 20 pts): Identifies administrative users who do not have an MFA device configured.

IAM_MFA_DISABLED_USER (High - 15 pts): Identifies standard IAM users who do not have an MFA device configured.

IAM_OLD_ACCESS_KEY (High - 15 pts): Flags active access keys older than 90 days.

IAM_UNUSED_ACCESS_KEY (Medium - 10 pts): Flags active access keys that have not been used in over 90 days.

IAM_ADMIN_ROLE_ASSUMED (High - 15 pts): Scans IAM roles to identify non-AWS services with unrestricted administrative access.

📉 Dynamic Score Calculation

Every scanned environment starts with a perfect score of 100. For each misconfiguration discovered, the engine applies a specific penalty deduction:

$$\text{Final Score} = \max(0, 100 - \sum \text{Deducted Points})$$

Score Grading Scale

Score Range

Letter Grade

Operational Status

$90 - 100$

A

Excellent

$80 - 89$

B

Good

$70 - 79$

C

Fair

$60 - 69$

D

Poor

$< 60$

F

Critical Risk

🛠️ Local Installation & Setup

Prerequisites

Python 3.9 or higher

An active AWS Account

AWS CLI configured locally with read-only permissions (aws configure)

Run Commands

# 1. Clone the project and navigate to the directory
cd CloudSentinel

# 2. Configure your Python virtual environment
python3 -m venv venv
source venv/bin/activate  # Windows users: .\venv\Scripts\activate

# 3. Install the required dependencies
pip install -r requirements.txt

# 4. Execute the orchestrator scan
python3 cloudscan_orchestrator.py

# 5. Launch the Streamlit dashboard
streamlit run dashboard.py


🛡️ Target AWS Read-Only Permissions

This project runs safely without modifying any live cloud resources. It requires the following read-only IAM permissions:

{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetBucket*",
        "s3:ListBucket*",
        "s3:GetEncryption",
        "s3:GetVersioning",
        "s3:GetLogging",
        "iam:ListUsers",
        "iam:ListRoles",
        "iam:GetUser*",
        "iam:ListAccessKeys",
        "iam:ListMFADevices",
        "iam:ListAttachedUserPolicies",
        "iam:ListAttachedRolePolicies",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}


📂 Project Directory Structure

CloudSentinel/
│
├── engine/                      <── Core Logic Package
│   ├── __init__.py              <── Initializes python package
│   ├── findings.py              <── Standardizes finding schema & registry
│   ├── severity.py              <── Severity evaluation rules
│   ├── scoring.py               <── Math scoring and grades calculator
│   ├── remediation.py           <── Generates triage runbooks
│   └── history.py               <── Stores chronological run snapshots
│
├── reports/                     <── Private local scan results (gitignored)
├── scan_history/                <── Private time-series metrics (gitignored)
│
├── .gitignore                   <── Blocks private local files from git
├── README.md                    <── Platform documentation
├── requirements.txt             <── External library requirements
├── cloudscan_orchestrator.py    <── Master coordinator pipeline script
└── dashboard.py                 <── Streamlit Slate-and-Emerald interface
