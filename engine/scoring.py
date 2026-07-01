"""
CloudSentinel Security Scoring Engine
Calculates security score (0-100) based on findings
"""

from typing import Dict, List, Optional, Tuple
from datetime import datetime
import json
from .findings import FindingRegistry


class SecurityScore:
    """
    Represents a single security score calculation.
    Includes breakdown by service and severity.
    """
    
    def __init__(
        self,
        registry: FindingRegistry,
        base_score: int = 100,
        timestamp: Optional[str] = None
    ):
        """
        Initialize security score.
        
        Args:
            registry: FindingRegistry with all findings
            base_score: Starting score (default 100)
            timestamp: When score was calculated
        """
        self.registry = registry
        self.base_score = base_score
        self.timestamp = timestamp or datetime.now().isoformat()
        
        # Calculate score
        self.total_points_deducted = 0
        self.findings_by_severity = registry.get_count_by_severity()
        self.findings_by_service = registry.get_count_by_service()
        
        # Calculate total deduction
        self._calculate_deductions()
        
        # Final score
        self.final_score = max(0, self.base_score - self.total_points_deducted)
    
    def _calculate_deductions(self) -> None:
        """
        Calculate total points deducted based on findings.
        Uses the severity_engine to get points.
        """
        from .severity import SeverityEngine
        
        severity_engine = SeverityEngine()
        
        for finding in self.registry.findings:
            points = severity_engine.get_points(finding.finding_type)
            self.total_points_deducted += points
    
    def get_score_percentage(self) -> int:
        """Get score as percentage (0-100)."""
        return self.final_score
    
    def get_score_grade(self) -> str:
        """
        Get letter grade based on score.
        A = 80+, B = 70+, C = 60+, D = 50+, F = <50
        """
        score = self.final_score
        if score >= 90:
            return "A (Excellent)"
        elif score >= 80:
            return "B (Good)"
        elif score >= 70:
            return "C (Fair)"
        elif score >= 60:
            return "D (Poor)"
        else:
            return "F (Critical)"
    
    def get_score_emoji(self) -> str:
        """Get emoji representation of score."""
        score = self.final_score
        if score >= 90:
            return "🟢"  # Green
        elif score >= 80:
            return "🟡"  # Yellow
        elif score >= 70:
            return "🟠"  # Orange
        else:
            return "🔴"  # Red
    
    def get_breakdown_by_severity(self) -> Dict[str, int]:
        """
        Get points deducted by severity level.
        
        Returns:
            Dict like {"CRITICAL": 60, "HIGH": 45, "MEDIUM": 20, "LOW": 0}
        """
        from .severity import SeverityEngine
        
        severity_engine = SeverityEngine()
        breakdown = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        
        for finding in self.registry.findings:
            points = severity_engine.get_points(finding.finding_type)
            breakdown[finding.severity] += points
        
        return breakdown
    
    def get_breakdown_by_service(self) -> Dict[str, int]:
        """
        Get points deducted by service.
        
        Returns:
            Dict like {"S3": 30, "IAM": 50}
        """
        from .severity import SeverityEngine
        
        severity_engine = SeverityEngine()
        breakdown = {}
        
        for finding in self.registry.findings:
            service = finding.service
            points = severity_engine.get_points(finding.finding_type)
            
            if service not in breakdown:
                breakdown[service] = 0
            breakdown[service] += points
        
        return breakdown
    
    def get_worst_findings(self, limit: int = 5) -> List:
        """
        Get the worst findings (CRITICAL and HIGH).
        
        Args:
            limit: Maximum number to return
            
        Returns:
            List of Finding objects
        """
        critical = self.registry.get_findings_by_severity("CRITICAL")
        high = self.registry.get_findings_by_severity("HIGH")
        
        worst = critical + high
        return worst[:limit]
    
    def to_dict(self) -> Dict:
        """Convert score to dictionary."""
        return {
            "timestamp": self.timestamp,
            "final_score": self.final_score,
            "base_score": self.base_score,
            "total_points_deducted": self.total_points_deducted,
            "grade": self.get_score_grade(),
            "total_findings": len(self.registry),
            "findings_by_severity": self.findings_by_severity,
            "findings_by_service": self.findings_by_service,
            "breakdown_by_severity": self.get_breakdown_by_severity(),
            "breakdown_by_service": self.get_breakdown_by_service()
        }
    
    def print_report(self) -> None:
        """Print a comprehensive security score report."""
        print("\n" + "="*80)
        print("🛡️  CLOUDSSENTINEL SECURITY SCORE REPORT")
        print("="*80)
        print(f"\nTimestamp: {self.timestamp}\n")
        
        # Main score card
        print(f"┌─────────────────────────────────────────────────────┐")
        print(f"│  Security Score: {self.final_score}/100  {self.get_score_emoji()}       │")
        print(f"│  Grade: {self.get_score_grade():<38} │")
        print(f"│  Points Deducted: {self.total_points_deducted}/{self.base_score}                      │")
        print(f"└─────────────────────────────────────────────────────┘\n")
        
        # Findings Summary
        print(f"📊 FINDINGS SUMMARY\n")
        print(f"  Total Findings: {len(self.registry)}")
        print(f"  🔴 CRITICAL: {self.findings_by_severity['CRITICAL']}")
        print(f"  🟠 HIGH:     {self.findings_by_severity['HIGH']}")
        print(f"  🟡 MEDIUM:   {self.findings_by_severity['MEDIUM']}")
        print(f"  🟢 LOW:      {self.findings_by_severity['LOW']}\n")
        
        # Points by Severity
        print(f"📉 POINTS DEDUCTED BY SEVERITY\n")
        breakdown_severity = self.get_breakdown_by_severity()
        print(f"  🔴 CRITICAL: -{breakdown_severity['CRITICAL']} points")
        print(f"  🟠 HIGH:     -{breakdown_severity['HIGH']} points")
        print(f"  🟡 MEDIUM:   -{breakdown_severity['MEDIUM']} points")
        print(f"  🟢 LOW:      -{breakdown_severity['LOW']} points\n")
        
        # Points by Service
        print(f"🔧 POINTS DEDUCTED BY SERVICE\n")
        breakdown_service = self.get_breakdown_by_service()
        for service in sorted(breakdown_service.keys()):
            points = breakdown_service[service]
            print(f"  {service}: -{points} points")
        print()
        
        # Top Issues
        worst = self.get_worst_findings(5)
        if worst:
            print(f"⚠️  TOP 5 CRITICAL/HIGH FINDINGS\n")
            for i, finding in enumerate(worst, 1):
                print(f"  {i}. [{finding.id}] {finding.title}")
                print(f"     Resource: {finding.resource}")
                print(f"     Severity: {finding.severity}\n")
        
        print("="*80 + "\n")
    
    def __repr__(self) -> str:
        return f"SecurityScore(score={self.final_score}/100, grade={self.get_score_grade()})"


class ScoringEngine:
    """
    Engine to calculate and track security scores over time.
    """
    
    def __init__(self):
        """Initialize scoring engine."""
        self.scores: List[SecurityScore] = []
    
    def calculate_score(self, registry: FindingRegistry) -> SecurityScore:
        """
        Calculate security score from a finding registry.
        
        Args:
            registry: FindingRegistry with findings
            
        Returns:
            SecurityScore object
        """
        score = SecurityScore(registry)
        self.scores.append(score)
        return score
    
    def get_latest_score(self) -> Optional[SecurityScore]:
        """Get the most recent score."""
        if self.scores:
            return self.scores[-1]
        return None
    
    def get_score_trend(self) -> Dict:
        """
        Get trending data for scores over time.
        
        Returns:
            Dict with trend information
        """
        if len(self.scores) < 2:
            return {"trend": "INSUFFICIENT_DATA", "change": 0}
        
        latest = self.scores[-1].final_score
        previous = self.scores[-2].final_score
        change = latest - previous
        
        trend = "IMPROVING" if change > 0 else "DECLINING" if change < 0 else "STABLE"
        
        return {
            "latest_score": latest,
            "previous_score": previous,
            "change": change,
            "trend": trend,
            "total_scans": len(self.scores)
        }
    
    def print_trend_report(self) -> None:
        """Print trending report."""
        trend = self.get_score_trend()
        
        if trend["trend"] == "INSUFFICIENT_DATA":
            print("⚠️  Need at least 2 scans to show trend\n")
            return
        
        latest = trend["latest_score"]
        previous = trend["previous_score"]
        change = trend["change"]
        trend_type = trend["trend"]
        
        print("\n" + "="*80)
        print("📈 SECURITY SCORE TREND")
        print("="*80 + "\n")
        
        print(f"Latest Score:   {latest}/100")
        print(f"Previous Score: {previous}/100")
        
        if change > 0:
            print(f"Change:         +{change} ↑ (IMPROVING) 🎉")
        elif change < 0:
            print(f"Change:         {change} ↓ (DECLINING) ⚠️")
        else:
            print(f"Change:         0 → (STABLE)")
        
        print(f"Scans Tracked:  {trend['total_scans']}")
        print("\n" + "="*80 + "\n")
    
    def save_scores_to_json(self, filename: str) -> None:
        """
        Save all scores to JSON.
        
        Args:
            filename: Path to save file
        """
        scores_data = [score.to_dict() for score in self.scores]
        with open(filename, 'w') as f:
            json.dump(scores_data, f, indent=2)
        print(f"✅ Scores saved to: {filename}")
    
    def __len__(self) -> int:
        """Return number of scores calculated."""
        return len(self.scores)