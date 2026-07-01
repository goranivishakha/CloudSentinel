"""
CloudSentinel Master Orchestrator
Runs complete security scan pipeline in one command
Coordinates: Inventory → Scanners → Engines → Reports
"""

import os
import sys
import json
import argparse
from datetime import datetime
from pathlib import Path

# Import engine modules
from engine.findings import Finding, FindingRegistry
from engine.severity import SeverityEngine
from engine.scoring import ScoringEngine
from engine.remediation import RemediationPlan, RemediationTracker
from engine.history import ScanHistory

# Import AWS clients
import boto3


class CloudSentinelOrchestrator:
    """
    Master orchestrator for complete CloudSentinel scan pipeline.
    """
    
    def __init__(self, verbose: bool = True):
        """
        Initialize orchestrator.
        
        Args:
            verbose: Print detailed progress
        """
        self.verbose = verbose
        self.start_time = datetime.now()
        self.report_dir = "reports"
        
        # Create reports directory
        if not os.path.exists(self.report_dir):
            os.makedirs(self.report_dir)
        
        # Initialize engines
        self.registry = FindingRegistry()
        self.severity_engine = SeverityEngine()
        self.scoring_engine = ScoringEngine()
        self.history = ScanHistory()
        
        # Initialize AWS clients
        self.s3_client = boto3.client('s3')
        self.iam_client = boto3.client('iam')
        self.sts_client = boto3.client('sts')
        
        # Get account info
        self._get_account_info()
    
    def _get_account_info(self) -> None:
        """Get AWS account metadata."""
        try:
            identity = self.sts_client.get_caller_identity()
            self.account_id = identity['Account']
            self.arn = identity['Arn']
        except Exception as e:
            print(f"⚠️  Could not get account info: {str(e)}")
            self.account_id = "unknown"
            self.arn = "unknown"
    
    def log(self, message: str = "") -> None:
        """Print message if verbose."""
        if self.verbose:
            print(message)
    
    # ========== PHASE 1: INVENTORY ==========
    
    def inventory_resources(self) -> dict:
        """Inventory all AWS resources."""
        self.log("\n" + "="*80)
        self.log("📊 PHASE 1: INVENTORY")
        self.log("="*80 + "\n")
        
        self.log("🔍 Counting AWS resources...\n")
        
        inventory = {
            "account_id": self.account_id,
            "scan_timestamp": datetime.now().isoformat(),
            "s3_buckets": 0,
            "iam_users": 0,
            "iam_roles": 0,
            "iam_policies": 0,
            "access_keys": 0
        }
        
        try:
            # Count S3 buckets
            s3_response = self.s3_client.list_buckets()
            inventory["s3_buckets"] = len(s3_response['Buckets'])
            self.log(f"📦 S3 Buckets: {inventory['s3_buckets']}")
        except Exception as e:
            self.log(f"⚠️  Could not count S3 buckets: {str(e)}")
        
        try:
            # Count IAM users
            iam_response = self.iam_client.list_users()
            inventory["iam_users"] = len(iam_response['Users'])
            self.log(f"👥 IAM Users: {inventory['iam_users']}")
        except Exception as e:
            self.log(f"⚠️  Could not count IAM users: {str(e)}")
        
        try:
            # Count IAM roles
            roles_response = self.iam_client.list_roles()
            inventory["iam_roles"] = len(roles_response['Roles'])
            self.log(f"🔐 IAM Roles: {inventory['iam_roles']}")
        except Exception as e:
            self.log(f"⚠️  Could not count IAM roles: {str(e)}")
        
        try:
            # Count access keys
            users = self.iam_client.list_users()['Users']
            for user in users:
                keys = self.iam_client.list_access_keys(UserName=user['UserName'])
                inventory["access_keys"] += len(keys['AccessKeyMetadata'])
            self.log(f"🔑 Access Keys: {inventory['access_keys']}")
        except Exception as e:
            self.log(f"⚠️  Could not count access keys: {str(e)}")
        
        self.log()
        return inventory
    
    # ========== PHASE 2: S3 SCANNING ==========
    
    def scan_s3(self) -> int:
        """Scan S3 buckets for security issues."""
        self.log("="*80)
        self.log("🔐 PHASE 2: S3 SECURITY SCAN")
        self.log("="*80 + "\n")
        
        findings_before = len(self.registry)
        s3_response = self.s3_client.list_buckets()
        buckets = s3_response['Buckets']
        
        self.log(f"📦 Scanning {len(buckets)} S3 buckets...\n")
        
        for bucket in buckets:
            bucket_name = bucket['Name']
            self.log(f"  🔎 {bucket_name}...")
            
            # Check 1: Versioning
            try:
                versioning = self.s3_client.get_bucket_versioning(Bucket=bucket_name)
                if versioning.get('Status') != 'Enabled':
                    finding = Finding(
                        title="S3 Bucket Versioning Disabled",
                        service="S3",
                        resource=bucket_name,
                        severity="MEDIUM",
                        evidence="get_bucket_versioning returned Status != 'Enabled'",
                        recommendation="Enable versioning for disaster recovery",
                        remediation_steps=[
                            "1. Go to AWS Console → S3 → bucket → Properties",
                            "2. Enable Versioning",
                            "3. Click Save"
                        ],
                        account_id=self.account_id,
                        finding_type="S3_VERSIONING_DISABLED",
                        risk_reason="Cannot recover accidentally deleted files"
                    )
                    self.registry.add_finding(finding)
            except Exception as e:
                pass
            
            # Check 2: Public Access Block
            try:
                public_access = self.s3_client.get_public_access_block(Bucket=bucket_name)
                config = public_access['PublicAccessBlockConfiguration']
                if not (config['BlockPublicAcls'] and config['BlockPublicPolicy']):
                    finding = Finding(
                        title="S3 Public Access Block Incomplete",
                        service="S3",
                        resource=bucket_name,
                        severity="HIGH",
                        evidence=f"BlockPublicAcls: {config.get('BlockPublicAcls')}, BlockPublicPolicy: {config.get('BlockPublicPolicy')}",
                        recommendation="Enable all public access block settings",
                        remediation_steps=[
                            "1. Go to AWS Console → S3 → bucket → Permissions",
                            "2. Click 'Block public access'",
                            "3. Enable all 4 checkboxes",
                            "4. Click Save"
                        ],
                        account_id=self.account_id,
                        finding_type="S3_PUBLIC_ACCESS_BLOCK_INCOMPLETE",
                        risk_reason="Bucket can be accidentally exposed"
                    )
                    self.registry.add_finding(finding)
            except self.s3_client.exceptions.NoSuchPublicAccessBlockConfiguration:
                finding = Finding(
                    title="S3 Public Access Block Not Configured",
                    service="S3",
                    resource=bucket_name,
                    severity="CRITICAL",
                    evidence="NoSuchPublicAccessBlockConfiguration",
                    recommendation="Configure public access block immediately",
                    remediation_steps=[
                        "1. URGENT: Configure block public access",
                        "2. Go to AWS Console → S3 → bucket → Permissions",
                        "3. Click 'Block public access'",
                        "4. Enable all 4 checkboxes"
                    ],
                    account_id=self.account_id,
                    finding_type="S3_PUBLIC_ACCESS_BLOCK_MISSING",
                    risk_reason="Bucket completely exposed to public"
                )
                self.registry.add_finding(finding)
            except Exception as e:
                pass
            
            # Check 3: Encryption
            try:
                encryption = self.s3_client.get_bucket_encryption(Bucket=bucket_name)
                if not encryption.get('ServerSideEncryptionConfiguration'):
                    finding = Finding(
                        title="S3 Bucket Encryption Disabled",
                        service="S3",
                        resource=bucket_name,
                        severity="HIGH",
                        evidence="No encryption configuration found",
                        recommendation="Enable server-side encryption",
                        remediation_steps=[
                            "1. Go to AWS Console → S3 → bucket → Properties",
                            "2. Click 'Edit' under Default encryption",
                            "3. Choose 'SSE-S3'",
                            "4. Click Save"
                        ],
                        account_id=self.account_id,
                        finding_type="S3_ENCRYPTION_DISABLED",
                        risk_reason="Data at rest is not protected"
                    )
                    self.registry.add_finding(finding)
            except self.s3_client.exceptions.ServerSideEncryptionConfigurationNotFoundError:
                finding = Finding(
                    title="S3 Bucket Encryption Not Configured",
                    service="S3",
                    resource=bucket_name,
                    severity="HIGH",
                    evidence="No encryption configuration",
                    recommendation="Configure encryption immediately",
                    remediation_steps=["Enable in S3 console"],
                    account_id=self.account_id,
                    finding_type="S3_ENCRYPTION_DISABLED",
                    risk_reason="Sensitive data unprotected"
                )
                self.registry.add_finding(finding)
            except Exception as e:
                pass
            
            # Check 4: Logging
            try:
                logging_config = self.s3_client.get_bucket_logging(Bucket=bucket_name)
                if not logging_config.get('LoggingEnabled'):
                    finding = Finding(
                        title="S3 Bucket Logging Disabled",
                        service="S3",
                        resource=bucket_name,
                        severity="MEDIUM",
                        evidence="No logging configured",
                        recommendation="Enable access logging",
                        remediation_steps=["Enable in S3 console"],
                        account_id=self.account_id,
                        finding_type="S3_LOGGING_DISABLED",
                        risk_reason="No audit trail"
                    )
                    self.registry.add_finding(finding)
            except Exception as e:
                pass
        
        s3_findings = len(self.registry) - findings_before
        self.log(f"\n✅ S3 Scan Complete: {s3_findings} issues found\n")
        return s3_findings
    
    # ========== PHASE 3: IAM SCANNING ==========
    
    def scan_iam(self) -> int:
        """Scan IAM for security issues."""
        self.log("="*80)
        self.log("🔐 PHASE 3: IAM SECURITY SCAN")
        self.log("="*80 + "\n")
        
        findings_before = len(self.registry)
        users = self.iam_client.list_users()['Users']
        
        self.log(f"👥 Scanning {len(users)} IAM users...\n")
        
        for user in users:
            username = user['UserName']
            self.log(f"  🔎 {username}...")
            
            # Check 1: MFA Status
            try:
                mfa_devices = self.iam_client.list_mfa_devices(UserName=username)['MFADevices']
                has_mfa = len(mfa_devices) > 0
                
                # Check if admin
                attached_policies = self.iam_client.list_attached_user_policies(UserName=username)['AttachedPolicies']
                has_admin = any('AdministratorAccess' in p['PolicyName'] for p in attached_policies)
                
                if has_admin and not has_mfa:
                    finding = Finding(
                        title=f"IAM Admin User '{username}' Without MFA",
                        service="IAM",
                        resource=username,
                        severity="CRITICAL",
                        evidence="User has AdminAccess, no MFA devices",
                        recommendation="Enable MFA on admin user immediately",
                        remediation_steps=[
                            f"1. Go to AWS Console → IAM → Users → {username}",
                            "2. Click 'Security credentials' tab",
                            "3. Click 'Assign MFA device'",
                            "4. Complete MFA setup and test"
                        ],
                        account_id=self.account_id,
                        finding_type="IAM_MFA_DISABLED_ADMIN_USER",
                        risk_reason="Admin without MFA = account takeover risk"
                    )
                    self.registry.add_finding(finding)
                
                elif not has_admin and not has_mfa:
                    finding = Finding(
                        title=f"IAM User '{username}' Without MFA",
                        service="IAM",
                        resource=username,
                        severity="HIGH",
                        evidence="No MFA devices configured",
                        recommendation="Enable MFA on all users",
                        remediation_steps=["Enable MFA in IAM console"],
                        account_id=self.account_id,
                        finding_type="IAM_MFA_DISABLED_USER",
                        risk_reason="Password compromise = account loss"
                    )
                    self.registry.add_finding(finding)
            
            except Exception as e:
                pass
            
            # Check 2: Access Keys
            try:
                access_keys = self.iam_client.list_access_keys(UserName=username)['AccessKeyMetadata']
                
                for key in access_keys:
                    key_id = key['AccessKeyId']
                    created = key['CreateDate']
                    key_age_days = (datetime.now(created.tzinfo) - created).days
                    
                    if key_age_days > 90:
                        finding = Finding(
                            title=f"Old Access Key for '{username}'",
                            service="IAM",
                            resource=f"{username}_{key_id[-4:]}",
                            severity="HIGH",
                            evidence=f"Key is {key_age_days} days old",
                            recommendation="Rotate access keys every 90 days",
                            remediation_steps=["Create new key and update applications"],
                            account_id=self.account_id,
                            finding_type="IAM_OLD_ACCESS_KEY",
                            risk_reason="Old credentials should be rotated"
                        )
                        self.registry.add_finding(finding)
            
            except Exception as e:
                pass
        
        iam_findings = len(self.registry) - findings_before
        self.log(f"\n✅ IAM Scan Complete: {iam_findings} issues found\n")
        return iam_findings
    
    # ========== PHASE 4: SEVERITY ASSESSMENT ==========
    
    def assess_severity(self) -> None:
        """Assess severity of all findings."""
        self.log("="*80)
        self.log("⚖️  PHASE 4: SEVERITY ASSESSMENT")
        self.log("="*80 + "\n")
        
        self.log(f"🔍 Assessing {len(self.registry)} findings...\n")
        
        for finding in self.registry.findings:
            assessed_severity = self.severity_engine.get_severity(finding.finding_type)
            finding.severity = assessed_severity
        
        counts = self.registry.get_count_by_severity()
        self.log(f"✅ Severity Assessment Complete:")
        self.log(f"   🔴 CRITICAL: {counts['CRITICAL']}")
        self.log(f"   🟠 HIGH:     {counts['HIGH']}")
        self.log(f"   🟡 MEDIUM:   {counts['MEDIUM']}")
        self.log(f"   🟢 LOW:      {counts['LOW']}\n")
    
    # ========== PHASE 5: SCORING ==========
    
    def calculate_score(self):
        """Calculate security score."""
        self.log("="*80)
        self.log("📊 PHASE 5: SECURITY SCORING")
        self.log("="*80 + "\n")
        
        self.score = self.scoring_engine.calculate_score(self.registry)
        
        self.log(f"✅ Security Score Calculated: {self.score.final_score}/100\n")
        
        return self.score
    
    # ========== PHASE 6: REMEDIATION PLANNING ==========
    
    def create_remediation_plan(self):
        """Create remediation plan."""
        self.log("="*80)
        self.log("🛠️  PHASE 6: REMEDIATION PLANNING")
        self.log("="*80 + "\n")
        
        self.plan = RemediationPlan(self.registry)
        summary = self.plan.get_summary()
        
        self.log(f"✅ Remediation Plan Created:")
        self.log(f"   Total Items: {summary['total_items']}")
        self.log(f"   Estimated Time: {summary['estimated_total_time_hours']} hours")
        self.log(f"   By Priority:")
        self.log(f"      🔴 IMMEDIATE: {summary['by_priority']['IMMEDIATE']}")
        self.log(f"      🟠 URGENT:    {summary['by_priority']['URGENT']}")
        self.log(f"      🟡 SOON:      {summary['by_priority']['SOON']}")
        self.log(f"      🟢 EVENTUAL:  {summary['by_priority']['EVENTUAL']}\n")
    
    # ========== PHASE 7: HISTORY TRACKING ==========
    
    def save_scan_history(self):
        """Save scan to history."""
        self.log("="*80)
        self.log("📅 PHASE 7: HISTORY TRACKING")
        self.log("="*80 + "\n")
        
        scan_id = self.history.add_scan(
            self.registry,
            self.score,
            f"Scan-{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        )
        
        self.log(f"✅ Scan saved to history: {scan_id}\n")
        
        # Show improvement if available
        improvement = self.history.get_improvement()
        if improvement is not None:
            self.log(f"📈 Overall Improvement: +{improvement} points\n")
    
    # ========== PHASE 8: COMPREHENSIVE REPORTING ==========
    
    def generate_reports(self):
        """Generate all reports."""
        self.log("="*80)
        self.log("📝 PHASE 8: GENERATING REPORTS")
        self.log("="*80 + "\n")
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Report 1: Findings Summary
        findings_file = os.path.join(self.report_dir, f"findings_{timestamp}.json")
        self.registry.save_to_json(findings_file)
        self.log(f"✅ Saved: Findings Summary ({os.path.basename(findings_file)})")
        
        # Report 2: Security Score
        score_file = os.path.join(self.report_dir, f"score_{timestamp}.json")
        with open(score_file, 'w') as f:
            json.dump(self.score.to_dict(), f, indent=2)
        self.log(f"✅ Saved: Security Score ({os.path.basename(score_file)})")
        
        # Report 3: Remediation Plan
        plan_file = os.path.join(self.report_dir, f"remediation_plan_{timestamp}.json")
        self.plan.save_to_json(plan_file)
        self.log(f"✅ Saved: Remediation Plan ({os.path.basename(plan_file)})")
        
        # Report 4: History CSV
        history_file = os.path.join(self.report_dir, f"history_{timestamp}.csv")
        self.history.export_csv(history_file)
        self.log(f"✅ Saved: History CSV ({os.path.basename(history_file)})")
        
        self.log()
    
    # ========== MAIN ORCHESTRATION ==========
    
    def run_complete_scan(self) -> dict:
        """
        Run complete CloudSentinel scan pipeline.
        
        Returns:
            Scan summary dictionary
        """
        print("\n" + "█"*80)
        print("█" + " "*78 + "█")
        print("█" + "  🛡️  CLOUDSSENTINEL: AUTOMATED AWS SECURITY SCAN".center(78) + "█")
        print("█" + " "*78 + "█")
        print("█"*80 + "\n")
        
        try:
            # Phase 1: Inventory
            inventory = self.inventory_resources()
            
            # Phase 2: S3 Scan
            s3_findings = self.scan_s3()
            
            # Phase 3: IAM Scan
            iam_findings = self.scan_iam()
            
            # Phase 4: Severity Assessment
            self.assess_severity()
            
            # Phase 5: Scoring
            score = self.calculate_score()
            
            # Phase 6: Remediation Planning
            self.create_remediation_plan()
            
            # Phase 7: History Tracking
            self.save_scan_history()
            
            # Phase 8: Generate Reports
            self.generate_reports()
            
            # Final Summary
            self._print_executive_summary()
            
            # Return summary
            return {
                "status": "SUCCESS",
                "inventory": inventory,
                "findings": len(self.registry),
                "score": score.final_score,
                "grade": score.get_score_grade(),
                "s3_findings": s3_findings,
                "iam_findings": iam_findings,
                "scan_duration_seconds": (datetime.now() - self.start_time).total_seconds()
            }
        
        except Exception as e:
            self.log(f"\n❌ ERROR: {str(e)}")
            return {"status": "FAILED", "error": str(e)}
    
    def _print_executive_summary(self) -> None:
        """Print executive summary."""
        print("\n" + "="*80)
        print("📊 EXECUTIVE SUMMARY")
        print("="*80 + "\n")
        
        # Score Card
        print(f"┌─────────────────────────────────────────────────────┐")
        print(f"│  Security Score: {self.score.final_score}/100  {self.score.get_score_emoji()}       │")
        print(f"│  Grade: {self.score.get_score_grade():<38} │")
        print(f"└─────────────────────────────────────────────────────┘\n")
        
        # Findings
        counts = self.registry.get_count_by_severity()
        print(f"📋 FINDINGS\n")
        print(f"  Total: {len(self.registry)}")
        print(f"  🔴 CRITICAL: {counts['CRITICAL']}")
        print(f"  🟠 HIGH:     {counts['HIGH']}")
        print(f"  🟡 MEDIUM:   {counts['MEDIUM']}")
        print(f"  🟢 LOW:      {counts['LOW']}\n")
        
        # Top Issues
        worst = self.score.get_worst_findings(3)
        if worst:
            print(f"⚠️  TOP ISSUES\n")
            for i, finding in enumerate(worst, 1):
                print(f"  {i}. {finding.title}")
                print(f"     Resource: {finding.resource}")
                print(f"     Priority: {finding.severity}\n")
        
        # Remediation Summary
        plan_summary = self.plan.get_summary()
        print(f"🛠️  REMEDIATION SUMMARY\n")
        print(f"  Items to Fix: {plan_summary['total_items']}")
        print(f"  Est. Time: {plan_summary['estimated_total_time_hours']} hours")
        print(f"  By Priority:")
        print(f"    🔴 IMMEDIATE: {plan_summary['by_priority']['IMMEDIATE']}")
        print(f"    🟠 URGENT:    {plan_summary['by_priority']['URGENT']}\n")
        
        # Improvement
        improvement = self.history.get_improvement()
        if improvement is not None and improvement > 0:
            print(f"📈 IMPROVEMENT\n")
            print(f"  Score improved +{improvement} points since last scan 🎉\n")
        
        print("="*80)
        print(f"\n✅ Scan Complete in {(datetime.now() - self.start_time).total_seconds():.1f} seconds")
        print(f"📁 Reports saved to: {self.report_dir}/\n")


# ========== COMMAND LINE INTERFACE ==========

def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="CloudSentinel: Automated AWS Security Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 cloudscan_orchestrator.py                 # Run full scan
  python3 cloudscan_orchestrator.py --quiet         # Minimal output
  python3 cloudscan_orchestrator.py --s3-only       # S3 only
  python3 cloudscan_orchestrator.py --iam-only      # IAM only
        """
    )
    
    parser.add_argument(
        '--quiet',
        action='store_true',
        help='Suppress verbose output'
    )
    
    parser.add_argument(
        '--s3-only',
        action='store_true',
        help='Scan S3 only (skip IAM)'
    )
    
    parser.add_argument(
        '--iam-only',
        action='store_true',
        help='Scan IAM only (skip S3)'
    )
    
    args = parser.parse_args()
    
    # Create orchestrator
    orchestrator = CloudSentinelOrchestrator(verbose=not args.quiet)
    
    # Run scan
    result = orchestrator.run_complete_scan()
    
    # Exit with appropriate code
    sys.exit(0 if result['status'] == 'SUCCESS' else 1)


if __name__ == "__main__":
    main()