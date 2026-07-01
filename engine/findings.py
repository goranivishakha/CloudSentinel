"""
CloudSentinel Findings Engine
Standardizes all security findings across all AWS services
"""

from datetime import datetime
from typing import List, Optional, Dict, Any
import json
import uuid

class Finding:
    """
    Standardized finding class.
    Every security issue becomes a Finding object.
    This is the foundation for scoring, reporting, and trending.
    """
    
    def __init__(
        self,
        title: str,
        service: str,
        resource: str,
        severity: str,
        evidence: str,
        recommendation: str,
        remediation_steps: List[str],
        account_id: Optional[str] = None,
        region: Optional[str] = None,
        finding_type: Optional[str] = None,
        cis_benchmark: Optional[str] = None,
        risk_reason: Optional[str] = None,
    ):
        """
        Initialize a Finding.
        
        Args:
            title: Human-readable issue title
            service: AWS service (S3, IAM, etc)
            resource: Affected resource name
            severity: CRITICAL, HIGH, MEDIUM, LOW
            evidence: Proof that issue exists (from API response)
            recommendation: What to do about it
            remediation_steps: Step-by-step fix instructions
            account_id: AWS account ID
            region: AWS region
            finding_type: Category (e.g., "S3_PUBLIC_ACCESS")
            cis_benchmark: CIS benchmark reference (e.g., "CIS AWS 2.1.5")
            risk_reason: Why this matters
        """
        
        # Core identification
        self.id = f"CS-{uuid.uuid4().hex[:8].upper()}"  # Unique ID like CS-A1B2C3D4
        self.title = title
        self.service = service
        self.resource = resource
        self.severity = severity
        self.finding_type = finding_type or f"{service}_{title.upper().replace(' ', '_')}"
        
        # Evidence and remediation
        self.evidence = evidence
        self.recommendation = recommendation
        self.remediation_steps = remediation_steps
        self.risk_reason = risk_reason
        
        # Context
        self.account_id = account_id
        self.region = region
        self.cis_benchmark = cis_benchmark
        
        # Timeline
        self.first_detected = datetime.now().isoformat()
        self.last_seen = datetime.now().isoformat()
        self.status = "OPEN"  # OPEN, IN_PROGRESS, RESOLVED, IGNORED
        
        # Metadata
        self.metadata = {}
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary for JSON serialization."""
        return {
            "id": self.id,
            "title": self.title,
            "service": self.service,
            "resource": self.resource,
            "severity": self.severity,
            "finding_type": self.finding_type,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
            "remediation_steps": self.remediation_steps,
            "risk_reason": self.risk_reason,
            "account_id": self.account_id,
            "region": self.region,
            "cis_benchmark": self.cis_benchmark,
            "first_detected": self.first_detected,
            "last_seen": self.last_seen,
            "status": self.status,
            "metadata": self.metadata
        }
    
    def to_json_str(self) -> str:
        """Convert finding to JSON string."""
        return json.dumps(self.to_dict(), indent=2)
    
    def __str__(self) -> str:
        """Pretty print a finding."""
        return f"""
╔════════════════════════════════════════════════════════════╗
║ {self.id} | {self.severity}
║ {self.title}
╠════════════════════════════════════════════════════════════╣
║ Service:   {self.service}
║ Resource:  {self.resource}
║ Status:    {self.status}
╠════════════════════════════════════════════════════════════╣
║ Evidence:      {self.evidence[:50]}...
║ Recommend:     {self.recommendation}
║ Risk Reason:   {self.risk_reason or 'N/A'}
╚════════════════════════════════════════════════════════════╝
        """
    
    def __repr__(self) -> str:
        return f"Finding(id={self.id}, severity={self.severity}, service={self.service})"


class FindingRegistry:
    """
    Central registry for all findings.
    Combines findings from all services (S3, IAM, etc).
    """
    
    def __init__(self):
        """Initialize empty finding registry."""
        self.findings: List[Finding] = []
        self.created_at = datetime.now().isoformat()
    
    def add_finding(self, finding: Finding) -> None:
        """
        Add a single finding to the registry.
        
        Args:
            finding: Finding object to add
        """
        if not isinstance(finding, Finding):
            raise TypeError("Must be a Finding object")
        self.findings.append(finding)
    
    def add_findings(self, findings: List[Finding]) -> None:
        """
        Add multiple findings at once.
        
        Args:
            findings: List of Finding objects
        """
        for finding in findings:
            self.add_finding(finding)
    
    def get_findings_by_severity(self, severity: str) -> List[Finding]:
        """
        Get all findings of a specific severity.
        
        Args:
            severity: CRITICAL, HIGH, MEDIUM, or LOW
            
        Returns:
            List of Finding objects
        """
        return [f for f in self.findings if f.severity == severity]
    
    def get_findings_by_service(self, service: str) -> List[Finding]:
        """
        Get all findings for a specific service.
        
        Args:
            service: S3, IAM, etc
            
        Returns:
            List of Finding objects
        """
        return [f for f in self.findings if f.service == service]
    
    def get_findings_by_status(self, status: str) -> List[Finding]:
        """
        Get findings by status.
        
        Args:
            status: OPEN, IN_PROGRESS, RESOLVED, IGNORED
            
        Returns:
            List of Finding objects
        """
        return [f for f in self.findings if f.status == status]
    
    def get_count_by_severity(self) -> Dict[str, int]:
        """
        Get count of findings by severity level.
        
        Returns:
            Dict like {"CRITICAL": 2, "HIGH": 5, "MEDIUM": 3, "LOW": 1}
        """
        counts = {
            "CRITICAL": len(self.get_findings_by_severity("CRITICAL")),
            "HIGH": len(self.get_findings_by_severity("HIGH")),
            "MEDIUM": len(self.get_findings_by_severity("MEDIUM")),
            "LOW": len(self.get_findings_by_severity("LOW")),
        }
        return counts
    
    def get_count_by_service(self) -> Dict[str, int]:
        """
        Get count of findings by service.
        
        Returns:
            Dict like {"S3": 5, "IAM": 3}
        """
        services = set(f.service for f in self.findings)
        counts = {service: len(self.get_findings_by_service(service)) for service in services}
        return counts
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert registry to dictionary."""
        return {
            "created_at": self.created_at,
            "total_findings": len(self.findings),
            "count_by_severity": self.get_count_by_severity(),
            "count_by_service": self.get_count_by_service(),
            "findings": [f.to_dict() for f in self.findings]
        }
    
    def save_to_json(self, filename: str) -> None:
        """
        Save all findings to JSON file.
        
        Args:
            filename: Path to save file
        """
        with open(filename, 'w') as f:
            json.dump(self.to_dict(), f, indent=2)
        print(f"✅ Findings saved to: {filename}")
    
    def print_summary(self) -> None:
        """Print a summary of all findings."""
        counts = self.get_count_by_severity()
        service_counts = self.get_count_by_service()
        
        print("\n" + "="*70)
        print("📋 FINDINGS SUMMARY")
        print("="*70)
        print(f"\nTotal Findings: {len(self.findings)}\n")
        
        print("By Severity:")
        print(f"  🔴 CRITICAL: {counts['CRITICAL']}")
        print(f"  🟠 HIGH:     {counts['HIGH']}")
        print(f"  🟡 MEDIUM:   {counts['MEDIUM']}")
        print(f"  🟢 LOW:      {counts['LOW']}")
        
        print("\nBy Service:")
        for service, count in sorted(service_counts.items()):
            print(f"  {service}: {count}")
        
        print("\n" + "="*70 + "\n")
    
    def __len__(self) -> int:
        """Return number of findings."""
        return len(self.findings)
    
    def __getitem__(self, index: int) -> Finding:
        """Get finding by index."""
        return self.findings[index]
    
    def __iter__(self):
        """Iterate over findings."""
        return iter(self.findings)