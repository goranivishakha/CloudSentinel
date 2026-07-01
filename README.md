# CloudSentinel

![Python](https://img.shields.io/badge/Python-3.9+-blue?style=flat-square&logo=python)
![AWS](https://img.shields.io/badge/AWS-Supported-orange?style=flat-square&logo=amazon-aws)
![Status](https://img.shields.io/badge/Status-Active_Development-brightgreen?style=flat-square)

CloudSentinel is an on-demand Cloud Security Posture Management (CSPM) tool built to identify common AWS misconfigurations, calculate an overall security score, and provide clear remediation runbooks. 

It is designed as a modular portfolio project to demonstrate practical cloud auditing, data normalization patterns, and infrastructure security principles.

---

## Key Capabilities

- **On-Demand Auditing**: Scans S3 buckets and IAM identities via `boto3`.
- **Data Normalization**: Converts raw AWS API outputs from different services into an identical `Finding` object format.
- **Rule-Based Severity Assessment**: Evaluates vulnerabilities against 11 baseline rules to assign risk levels (Critical, High, Medium, Low).
- **Postures & Scoring**: Computes a dynamic security score (0-100 scale) based on deterministic point deductions.
- **Triage Optimization**: Builds prioritized remediation queues with time estimates and clear execution steps.
- **Visual Portal**: Features a minimalist Slate-and-Emerald web dashboard built with Streamlit and Plotly.

## System Architecture

```text
[ cloudscan_orchestrator.py ] <── Pipeline Coordinator (CLI / UI Entrypoint)
              │
              ├───► [ S3 Scanner ]   ───► Audits Buckets, Blocks, & Encryption
              └───► [ IAM Scanner ]  ───► Audits Users, MFA, & Access Keys
              │
              ▼
    [ engine/findings.py ]   <── Data Normalization into Standard Finding Objects
              │
              ▼
[ engine/severity.py & scoring.py ] <── Rule Engine & Dynamic Point Deductions (0-100)
              │
              ▼
[ engine/remediation.py & history.py ] <── Generates Actionable Runbooks & Saves Logs
              │
              ▼
       [ dashboard.py ]      <── Minimalist Slate & Emerald Web Portal
```

## This project demonstrates:
- Cloud security fundamentals (AWS S3, IAM, MFA, encryption)
- Software architecture (modular engines, separation of concerns)
- Python best practices (OOP, caching, error handling)
- DevSecOps thinking (findings → scoring → remediation → trending)
- UI/UX design (Streamlit dashboard with professional styling)

## 🛠️ Local Installation & Setup

#### Prerequisites

Python 3.9 or higher

An active AWS Account

AWS CLI configured locally with read-only permissions (aws configure)

Run Commands

#### 1. Clone the project and navigate to the directory
cd CloudSentinel

#### 2. Configure your Python virtual environment
python3 -m venv venv or python -m venv venv
###### Windows users: .\venv\Scripts\activate

#### 3. Install the required dependencies
pip install -r requirements.txt

#### 4. Execute the orchestrator scan
python3 cloudscan_orchestrator.py or python cloudscan_orchestrator.py

#### 5. Launch the Streamlit dashboard
streamlit run dashboard.py

## 🔒 Security Audits & Rules Checked

### 📦 S3 Storage Configuration Checks

S3_PUBLIC_WRITE_ACCESS (Critical - 20 pts): Flags if a bucket policy allows anonymous write access.

S3_PUBLIC_ACCESS_BLOCK_MISSING (Critical - 20 pts): Flags if S3 Block Public Access is completely disabled.

S3_PUBLIC_READ_ACCESS (High - 15 pts): Flags if a bucket allows open reading via policy or ACL.

S3_ENCRYPTION_DISABLED (High - 15 pts): Checks if default server-side encryption is missing.

S3_VERSIONING_DISABLED (Medium - 10 pts): Flags if versioning is disabled, exposing data to accidental deletion.

S3_LOGGING_DISABLED (Medium - 10 pts): Flags if server access logging is disabled.

### 👥 IAM Identity Configuration Checks

IAM_MFA_DISABLED_ADMIN_USER (Critical - 20 pts): Identifies administrative users who do not have an MFA device configured.

IAM_MFA_DISABLED_USER (High - 15 pts): Identifies standard IAM users who do not have an MFA device configured.

IAM_OLD_ACCESS_KEY (High - 15 pts): Flags active access keys older than 90 days.

IAM_UNUSED_ACCESS_KEY (Medium - 10 pts): Flags active access keys that have not been used in over 90 days.

IAM_ADMIN_ROLE_ASSUMED (High - 15 pts): Scans IAM roles to identify non-AWS services with unrestricted administrative access.

## 📉 Dynamic Score Calculation

Every scanned environment starts with a perfect score of 100. For each misconfiguration discovered, the engine applies a specific penalty deduction:

$$\text{Final Score} = \max(0, 100 - \sum \text{Deducted Points})$$

### Grading Scale

| Score Range | Assigned Grade | Environmental Status |
| :--- | :---: | :--- |
| **90 - 100** | A | Excellent Security Posture |
| **80 - 89**  | B | Good Baseline Security |
| **70 - 79**  | C | Fair Posture (Remediation Due) |
| **60 - 69**  | D | Poor Environment Hygiene |
| **< 60**     | F | Critical Risks Detected |

## Who Is This For?

This project is designed for:
- **Cloud Security Engineers** learning CSPM architecture
- **DevSecOps Teams** wanting automated security auditing
- **AWS Learners** understanding real-world security patterns
- **Portfolio Builders** demonstrating cloud security skills
- **Interview Prep** showing architectural thinking to recruiters

## 🛡️ Target AWS Read-Only Permissions

This project runs safely without modifying any live cloud resources. It requires the following read-only IAM permissions:

```json
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

```
```text
### 📂 Project Directory Structure

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
