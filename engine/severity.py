"""
CloudSentinel Severity Engine
Rule-based assessment of finding severity
"""

from typing import Dict, List, Optional
from enum import Enum
import json

class SeverityLevel(Enum):
    """Severity levels for findings."""
    CRITICAL = "CRITICAL"  # Fix immediately, security incident risk
    HIGH = "HIGH"           # Fix ASAP, significant risk
    MEDIUM = "MEDIUM"       # Fix soon, moderate risk
    LOW = "LOW"             # Fix eventually, informational
    INFORMATIONAL = "INFORMATIONAL"  # Not a risk, just good to know


class SeverityRule:
    """
    A single severity rule.
    Maps a finding type to a severity level.
    """
    
    def __init__(
        self,
        finding_type: str,
        severity: str,
        description: str,
        points_deducted: int
    ):
        """
        Initialize a severity rule.
        
        Args:
            finding_type: Type of finding (e.g., "S3_PUBLIC_READ")
            severity: CRITICAL, HIGH, MEDIUM, LOW
            description: Why this severity?
            points_deducted: Points removed from security score (STEP 6 uses this)
        """
        self.finding_type = finding_type
        self.severity = severity
        self.description = description
        self.points_deducted = points_deducted
    
    def __repr__(self) -> str:
        return f"Rule({self.finding_type} → {self.severity})"


class SeverityEngine:
    """
    Central rules engine for assessing finding severity.
    This is where you define what makes something CRITICAL vs HIGH.
    """
    
    def __init__(self):
        """Initialize with default severity rules."""
        self.rules: Dict[str, SeverityRule] = {}
        self._load_default_rules()
    
    def _load_default_rules(self) -> None:
        """Load default severity rules based on industry best practices."""
        
        # ========== S3 RULES ==========
        
        # PUBLIC ACCESS (Most dangerous)
        self.add_rule(SeverityRule(
            finding_type="S3_PUBLIC_WRITE_ACCESS",
            severity="CRITICAL",
            description="Anyone can upload/delete objects - ransomware risk",
            points_deducted=20
        ))
        
        self.add_rule(SeverityRule(
            finding_type="S3_PUBLIC_READ_ACCESS",
            severity="HIGH",
            description="Anyone can read all objects - data breach risk",
            points_deducted=15
        ))
        
        self.add_rule(SeverityRule(
            finding_type="S3_PUBLIC_ACCESS_BLOCK_INCOMPLETE",
            severity="HIGH",
            description="Public access block not fully enabled - easy to misconfigure",
            points_deducted=15
        ))
        
        self.add_rule(SeverityRule(
            finding_type="S3_PUBLIC_ACCESS_BLOCK_MISSING",
            severity="CRITICAL",
            description="No public access block - completely exposed to accidents",
            points_deducted=20
        ))
        
        # ENCRYPTION (Data protection)
        self.add_rule(SeverityRule(
            finding_type="S3_ENCRYPTION_DISABLED",
            severity="HIGH",
            description="Objects not encrypted at rest - regulatory violation",
            points_deducted=15
        ))
        
        # VERSIONING (Disaster recovery)
        self.add_rule(SeverityRule(
            finding_type="S3_VERSIONING_DISABLED",
            severity="MEDIUM",
            description="Cannot recover deleted/overwritten files",
            points_deducted=10
        ))
        
        # LOGGING (Audit trail)
        self.add_rule(SeverityRule(
            finding_type="S3_LOGGING_DISABLED",
            severity="MEDIUM",
            description="No audit trail of who accessed what",
            points_deducted=10
        ))
        
        # ========== IAM RULES ==========
        
        # ADMIN ACCESS (Maximum privilege)
        self.add_rule(SeverityRule(
            finding_type="IAM_ADMIN_USER",
            severity="CRITICAL",
            description="User has unrestricted admin access - catastrophic if compromised",
            points_deducted=20
        ))
        
        self.add_rule(SeverityRule(
            finding_type="IAM_ADMIN_ROLE_ASSUMED",
            severity="CRITICAL",
            description="Service role has admin access - can do anything",
            points_deducted=20
        ))
        
        # MFA (Identity protection)
        self.add_rule(SeverityRule(
            finding_type="IAM_MFA_DISABLED_ADMIN_USER",
            severity="CRITICAL",
            description="Admin without MFA - one password away from account takeover",
            points_deducted=20
        ))
        
        self.add_rule(SeverityRule(
            finding_type="IAM_MFA_DISABLED_USER",
            severity="HIGH",
            description="Non-admin user without MFA - credential compromise risk",
            points_deducted=15
        ))
        
        # ACCESS KEYS (Long-term credentials)
        self.add_rule(SeverityRule(
            finding_type="IAM_UNUSED_ACCESS_KEY",
            severity="MEDIUM",
            description="Key not used in 90 days - should be rotated or deleted",
            points_deducted=10
        ))
        
        self.add_rule(SeverityRule(
            finding_type="IAM_OLD_ACCESS_KEY",
            severity="HIGH",
            description="Access key >90 days old - should be rotated",
            points_deducted=15
        ))
        
        # PERMISSIONS (Principle of least privilege)
        self.add_rule(SeverityRule(
            finding_type="IAM_EXCESSIVE_PERMISSIONS",
            severity="HIGH",
            description="User has more permissions than role requires",
            points_deducted=15
        ))
        
        # ========== GENERAL RULES ==========
        
        self.add_rule(SeverityRule(
            finding_type="AUDIT_LOGGING_DISABLED",
            severity="MEDIUM",
            description="CloudTrail not logging - no forensics capability",
            points_deducted=10
        ))
    
    def add_rule(self, rule: SeverityRule) -> None:
        """
        Add a severity rule to the engine.
        
        Args:
            rule: SeverityRule object
        """
        self.rules[rule.finding_type] = rule
    
    def get_severity(self, finding_type: str) -> Optional[str]:
        """
        Get severity level for a finding type.
        
        Args:
            finding_type: Type of finding
            
        Returns:
            Severity string (CRITICAL, HIGH, MEDIUM, LOW)
        """
        rule = self.rules.get(finding_type)
        if rule:
            return rule.severity
        
        # Default to MEDIUM if not in rules
        print(f"⚠️ Warning: Unknown finding type '{finding_type}' - defaulting to MEDIUM")
        return "MEDIUM"
    
    def get_points(self, finding_type: str) -> int:
        """
        Get points deducted for a finding type.
        Used by scoring engine (STEP 6).
        
        Args:
            finding_type: Type of finding
            
        Returns:
            Points deducted
        """
        rule = self.rules.get(finding_type)
        if rule:
            return rule.points_deducted
        return 5  # Default to 5 points
    
    def get_description(self, finding_type: str) -> str:
        """
        Get human-readable description of why this severity.
        
        Args:
            finding_type: Type of finding
            
        Returns:
            Description string
        """
        rule = self.rules.get(finding_type)
        if rule:
            return rule.description
        return "No description available"
    
    def list_rules(self) -> None:
        """Print all available rules."""
        print("\n" + "="*80)
        print("📋 SEVERITY RULES")
        print("="*80 + "\n")
        
        # Group by severity
        critical = [r for r in self.rules.values() if r.severity == "CRITICAL"]
        high = [r for r in self.rules.values() if r.severity == "HIGH"]
        medium = [r for r in self.rules.values() if r.severity == "MEDIUM"]
        low = [r for r in self.rules.values() if r.severity == "LOW"]
        
        print(f"🔴 CRITICAL ({len(critical)} rules):")
        for rule in critical:
            print(f"   {rule.finding_type}")
            print(f"   → {rule.description}")
            print(f"   → -${rule.points_deducted} points\n")
        
        print(f"🟠 HIGH ({len(high)} rules):")
        for rule in high:
            print(f"   {rule.finding_type}")
            print(f"   → {rule.description}")
            print(f"   → -{rule.points_deducted} points\n")
        
        print(f"🟡 MEDIUM ({len(medium)} rules):")
        for rule in medium:
            print(f"   {rule.finding_type}")
            print(f"   → {rule.description}")
            print(f"   → -{rule.points_deducted} points\n")
        
        print("="*80 + "\n")
    
    def save_rules_to_json(self, filename: str) -> None:
        """
        Save all rules to JSON (for auditing/documentation).
        
        Args:
            filename: Path to save file
        """
        rules_dict = {}
        for finding_type, rule in self.rules.items():
            rules_dict[finding_type] = {
                "severity": rule.severity,
                "description": rule.description,
                "points_deducted": rule.points_deducted
            }
        
        with open(filename, 'w') as f:
            json.dump(rules_dict, f, indent=2)
        print(f"✅ Rules saved to: {filename}")
    
    def __len__(self) -> int:
        """Return number of rules."""
        return len(self.rules)
    
    def __repr__(self) -> str:
        return f"SeverityEngine({len(self.rules)} rules)"