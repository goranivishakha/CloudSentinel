"""
CloudSentinel Safe Remediation Engine
Generates actionable, safe remediation recommendations
(Does NOT auto-remediate - only recommends)
"""

from typing import Dict, List, Optional, Tuple
from datetime import datetime
from enum import Enum
from .findings import Finding, FindingRegistry


class RemediationPriority(Enum):
    """Priority levels for remediation actions."""
    IMMEDIATE = "IMMEDIATE"      # Fix now (CRITICAL findings)
    URGENT = "URGENT"            # Fix within 24 hours (HIGH findings)
    SOON = "SOON"                # Fix within 1 week (MEDIUM findings)
    EVENTUAL = "EVENTUAL"        # Fix when convenient (LOW findings)


class RemediationPlan:
    """
    Represents a complete remediation plan.
    Groups findings by priority and provides step-by-step fixes.
    """
    
    def __init__(self, registry: FindingRegistry):
        """
        Initialize remediation plan from findings.
        
        Args:
            registry: FindingRegistry with findings to remediate
        """
        self.registry = registry
        self.created_at = datetime.now().isoformat()
        self.plan_items: List[Dict] = []
        
        # Build the plan
        self._build_remediation_plan()
    
    def _build_remediation_plan(self) -> None:
        """Build prioritized remediation plan."""
        
        # Organize findings by priority
        critical = self.registry.get_findings_by_severity("CRITICAL")
        high = self.registry.get_findings_by_severity("HIGH")
        medium = self.registry.get_findings_by_severity("MEDIUM")
        low = self.registry.get_findings_by_severity("LOW")
        
        # Create plan items
        for finding in critical:
            self.plan_items.append(self._create_plan_item(finding, RemediationPriority.IMMEDIATE))
        
        for finding in high:
            self.plan_items.append(self._create_plan_item(finding, RemediationPriority.URGENT))
        
        for finding in medium:
            self.plan_items.append(self._create_plan_item(finding, RemediationPriority.SOON))
        
        for finding in low:
            self.plan_items.append(self._create_plan_item(finding, RemediationPriority.EVENTUAL))
    
    def _create_plan_item(self, finding: Finding, priority: RemediationPriority) -> Dict:
        """
        Create a single remediation plan item.
        
        Args:
            finding: Finding to remediate
            priority: Priority level
            
        Returns:
            Plan item dictionary
        """
        return {
            "finding_id": finding.id,
            "priority": priority.value,
            "title": finding.title,
            "service": finding.service,
            "resource": finding.resource,
            "severity": finding.severity,
            "recommendation": finding.recommendation,
            "steps": finding.remediation_steps,
            "risk_reason": finding.risk_reason,
            "estimated_time_minutes": self._estimate_time(finding.severity),
            "status": "NOT_STARTED",  # NOT_STARTED, IN_PROGRESS, COMPLETED, SKIPPED
            "assigned_to": None,
            "deadline": self._calculate_deadline(priority),
            "notes": ""
        }
    
    def _estimate_time(self, severity: str) -> int:
        """Estimate remediation time in minutes."""
        estimates = {
            "CRITICAL": 15,    # Quick critical fixes
            "HIGH": 30,        # Might require waiting/testing
            "MEDIUM": 20,      # Moderate complexity
            "LOW": 10          # Simple fixes
        }
        return estimates.get(severity, 15)
    
    def _calculate_deadline(self, priority: RemediationPriority) -> str:
        """Calculate deadline based on priority."""
        from datetime import timedelta
        
        deadlines = {
            RemediationPriority.IMMEDIATE: timedelta(hours=4),
            RemediationPriority.URGENT: timedelta(days=1),
            RemediationPriority.SOON: timedelta(days=7),
            RemediationPriority.EVENTUAL: timedelta(days=30)
        }
        
        deadline = datetime.now() + deadlines[priority]
        return deadline.isoformat()
    
    def get_plan_by_priority(self, priority: str) -> List[Dict]:
        """
        Get all plan items for a specific priority.
        
        Args:
            priority: IMMEDIATE, URGENT, SOON, or EVENTUAL
            
        Returns:
            List of plan items
        """
        return [item for item in self.plan_items if item["priority"] == priority]
    
    def get_plan_by_service(self, service: str) -> List[Dict]:
        """
        Get all plan items for a specific service.
        
        Args:
            service: S3, IAM, etc.
            
        Returns:
            List of plan items
        """
        return [item for item in self.plan_items if item["service"] == service]
    
    def get_plan_by_status(self, status: str) -> List[Dict]:
        """
        Get plan items by remediation status.
        
        Args:
            status: NOT_STARTED, IN_PROGRESS, COMPLETED, SKIPPED
            
        Returns:
            List of plan items
        """
        return [item for item in self.plan_items if item["status"] == status]
    
    def update_item_status(self, finding_id: str, status: str, notes: str = "") -> bool:
        """
        Update status of a remediation item.
        
        Args:
            finding_id: Finding ID to update
            status: New status
            notes: Optional notes about remediation
            
        Returns:
            True if updated, False if not found
        """
        for item in self.plan_items:
            if item["finding_id"] == finding_id:
                item["status"] = status
                item["notes"] = notes
                item["last_updated"] = datetime.now().isoformat()
                return True
        return False
    
    def assign_to(self, finding_id: str, assigned_to: str) -> bool:
        """
        Assign remediation to a person.
        
        Args:
            finding_id: Finding ID
            assigned_to: Person's name/email
            
        Returns:
            True if assigned, False if not found
        """
        for item in self.plan_items:
            if item["finding_id"] == finding_id:
                item["assigned_to"] = assigned_to
                return True
        return False
    
    def get_summary(self) -> Dict:
        """Get summary statistics."""
        immediate = len(self.get_plan_by_priority("IMMEDIATE"))
        urgent = len(self.get_plan_by_priority("URGENT"))
        soon = len(self.get_plan_by_priority("SOON"))
        eventual = len(self.get_plan_by_priority("EVENTUAL"))
        
        total_time = sum(item["estimated_time_minutes"] for item in self.plan_items)
        
        return {
            "total_items": len(self.plan_items),
            "by_priority": {
                "IMMEDIATE": immediate,
                "URGENT": urgent,
                "SOON": soon,
                "EVENTUAL": eventual
            },
            "by_status": {
                "NOT_STARTED": len(self.get_plan_by_status("NOT_STARTED")),
                "IN_PROGRESS": len(self.get_plan_by_status("IN_PROGRESS")),
                "COMPLETED": len(self.get_plan_by_status("COMPLETED")),
                "SKIPPED": len(self.get_plan_by_status("SKIPPED"))
            },
            "estimated_total_time_minutes": total_time,
            "estimated_total_time_hours": round(total_time / 60, 1)
        }
    
    def print_plan(self, priority_filter: Optional[str] = None) -> None:
        """
        Print remediation plan in readable format.
        
        Args:
            priority_filter: Optional filter (IMMEDIATE, URGENT, etc.)
        """
        if priority_filter:
            items = self.get_plan_by_priority(priority_filter)
            title = f"{priority_filter} Priority Remediation Plan"
        else:
            items = self.plan_items
            title = "Complete Remediation Plan"
        
        print("\n" + "="*80)
        print(f"🛠️  {title}")
        print("="*80 + "\n")
        
        summary = self.get_summary()
        
        print(f"Total Items: {summary['total_items']}")
        print(f"Estimated Time: {summary['estimated_total_time_hours']} hours\n")
        
        print(f"By Priority:")
        print(f"  🔴 IMMEDIATE: {summary['by_priority']['IMMEDIATE']} (Fix within 4 hours)")
        print(f"  🟠 URGENT:    {summary['by_priority']['URGENT']} (Fix within 24 hours)")
        print(f"  🟡 SOON:      {summary['by_priority']['SOON']} (Fix within 1 week)")
        print(f"  🟢 EVENTUAL:  {summary['by_priority']['EVENTUAL']} (Fix within 1 month)\n")
        
        if items:
            for i, item in enumerate(items, 1):
                print(f"{i}. [{item['finding_id']}] {item['title']}")
                print(f"   Service: {item['service']} | Resource: {item['resource']}")
                print(f"   Priority: {item['priority']} | Time: {item['estimated_time_minutes']} min")
                print(f"   Recommendation: {item['recommendation']}\n")
                print(f"   📋 Steps:")
                for j, step in enumerate(item['steps'], 1):
                    print(f"      {j}. {step}")
                print()
        else:
            print("No items match this filter.\n")
        
        print("="*80 + "\n")
    
    def print_quick_reference(self) -> None:
        """Print quick reference card for immediate fixes."""
        immediate = self.get_plan_by_priority("IMMEDIATE")
        
        if not immediate:
            print("\n✅ No IMMEDIATE priority items - good news!\n")
            return
        
        print("\n" + "="*80)
        print("⚡ IMMEDIATE ACTION REQUIRED")
        print("="*80 + "\n")
        
        for item in immediate:
            print(f"🔴 {item['title']}")
            print(f"   Resource: {item['resource']}")
            print(f"   Deadline: {item['deadline']}")
            print(f"   Risk: {item['risk_reason']}\n")
            print(f"   ➜ Quick Fix:")
            for step in item['steps'][:3]:  # First 3 steps
                print(f"      • {step}")
            if len(item['steps']) > 3:
                print(f"      ... ({len(item['steps']) - 3} more steps)")
            print()
        
        print("="*80 + "\n")
    
    def to_dict(self) -> Dict:
        """Convert plan to dictionary."""
        return {
            "created_at": self.created_at,
            "summary": self.get_summary(),
            "plan_items": self.plan_items
        }
    
    def save_to_json(self, filename: str) -> None:
        """Save plan to JSON."""
        import json
        with open(filename, 'w') as f:
            json.dump(self.to_dict(), f, indent=2)
        print(f"✅ Remediation plan saved to: {filename}")


class RemediationTracker:
    """
    Tracks remediation progress over time.
    Shows what's been fixed and what's still pending.
    """
    
    def __init__(self, plan: RemediationPlan):
        """Initialize tracker."""
        self.plan = plan
        self.created_at = datetime.now().isoformat()
    
    def get_completion_percentage(self) -> float:
        """Get % of items completed."""
        total = len(self.plan.plan_items)
        if total == 0:
            return 100.0
        completed = len(self.plan.get_plan_by_status("COMPLETED"))
        return round((completed / total) * 100, 1)
    
    def get_progress_summary(self) -> Dict:
        """Get progress summary."""
        summary = self.plan.get_summary()
        completion = self.get_completion_percentage()
        
        return {
            "total_findings": summary['total_items'],
            "completed": len(self.plan.get_plan_by_status("COMPLETED")),
            "in_progress": len(self.plan.get_plan_by_status("IN_PROGRESS")),
            "not_started": len(self.plan.get_plan_by_status("NOT_STARTED")),
            "skipped": len(self.plan.get_plan_by_status("SKIPPED")),
            "completion_percentage": completion
        }
    
    def print_progress(self) -> None:
        """Print progress report."""
        progress = self.get_progress_summary()
        completion = progress['completion_percentage']
        
        # Progress bar
        filled = int(completion / 5)  # 20 chars for 100%
        bar = "█" * filled + "░" * (20 - filled)
        
        print("\n" + "="*80)
        print("📈 REMEDIATION PROGRESS")
        print("="*80 + "\n")
        
        print(f"Completion: [{bar}] {completion}%\n")
        
        print(f"Completed:    {progress['completed']} ✅")
        print(f"In Progress:  {progress['in_progress']} 🔄")
        print(f"Not Started:  {progress['not_started']} ⏳")
        print(f"Skipped:      {progress['skipped']} ⊘")
        print(f"Total:        {progress['total_findings']}")
        
        print("\n" + "="*80 + "\n")