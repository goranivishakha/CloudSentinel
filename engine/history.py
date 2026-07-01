"""
CloudSentinel Scan History Engine
Tracks all scans over time for trending analysis
"""

import os
import json
from datetime import datetime
from typing import List, Dict, Optional
from .findings import FindingRegistry
from .scoring import SecurityScore


class ScanSnapshot:
    """
    Represents a single point-in-time scan.
    Includes findings, score, and metadata.
    """
    
    def __init__(
        self,
        scan_id: str,
        registry: FindingRegistry,
        score: SecurityScore,
        scan_name: Optional[str] = None
    ):
        """
        Initialize scan snapshot.
        
        Args:
            scan_id: Unique scan identifier
            registry: FindingRegistry from scan
            score: SecurityScore from scan
            scan_name: Optional human-readable name
        """
        self.scan_id = scan_id
        self.scan_name = scan_name or f"Scan-{scan_id}"
        self.timestamp = datetime.now().isoformat()
        self.registry = registry
        self.score = score
        
        # Capture counts
        self.total_findings = len(registry)
        self.findings_by_severity = registry.get_count_by_severity()
        self.findings_by_service = registry.get_count_by_service()
    
    def to_dict(self) -> Dict:
        """Convert snapshot to dictionary."""
        return {
            "scan_id": self.scan_id,
            "scan_name": self.scan_name,
            "timestamp": self.timestamp,
            "security_score": self.score.final_score,
            "grade": self.score.get_score_grade(),
            "total_findings": self.total_findings,
            "findings_by_severity": self.findings_by_severity,
            "findings_by_service": self.findings_by_service,
            "points_deducted": self.score.total_points_deducted
        }


class ScanHistory:
    """
    Central repository for all scans over time.
    Enables trending, comparison, and progress tracking.
    """
    
    def __init__(self, history_dir: str = "scan_history"):
        """
        Initialize scan history.
        
        Args:
            history_dir: Directory to store historical scans
        """
        self.history_dir = history_dir
        self.snapshots: List[ScanSnapshot] = []
        
        # Create history directory if it doesn't exist
        if not os.path.exists(self.history_dir):
            os.makedirs(self.history_dir)
        
        # Load existing history
        self._load_history()
    
    def _load_history(self) -> None:
        """Load existing scan history from files."""
        try:
            # List all scan files in history directory
            scan_files = [f for f in os.listdir(self.history_dir) if f.startswith('scan_') and f.endswith('.json')]
            
            for scan_file in sorted(scan_files):
                try:
                    with open(os.path.join(self.history_dir, scan_file), 'r') as f:
                        data = json.load(f)
                        # Note: We load the metadata, not the full registry
                        # Full registry would be too large to keep in memory
                except Exception as e:
                    print(f"⚠️  Could not load {scan_file}: {str(e)}")
        except Exception as e:
            print(f"⚠️  Could not load scan history: {str(e)}")
    
    def add_scan(self, registry: FindingRegistry, score: SecurityScore, scan_name: Optional[str] = None) -> str:
        """
        Add a new scan to history.
        
        Args:
            registry: FindingRegistry from scan
            score: SecurityScore from scan
            scan_name: Optional name for scan
            
        Returns:
            Scan ID
        """
        # Create unique scan ID
        scan_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Create snapshot
        snapshot = ScanSnapshot(scan_id, registry, score, scan_name)
        self.snapshots.append(snapshot)
        
        # Save to JSON
        self._save_scan(snapshot)
        
        return scan_id
    
    def _save_scan(self, snapshot: ScanSnapshot) -> None:
        """
        Save scan snapshot to JSON file.
        
        Args:
            snapshot: ScanSnapshot to save
        """
        filename = os.path.join(self.history_dir, f"scan_{snapshot.scan_id}.json")
        
        with open(filename, 'w') as f:
            json.dump(snapshot.to_dict(), f, indent=2)
    
    def get_all_scans(self) -> List[ScanSnapshot]:
        """Get all scans in chronological order."""
        return sorted(self.snapshots, key=lambda s: s.timestamp)
    
    def get_latest_scan(self) -> Optional[ScanSnapshot]:
        """Get most recent scan."""
        if self.snapshots:
            return sorted(self.snapshots, key=lambda s: s.timestamp)[-1]
        return None
    
    def get_scan_by_id(self, scan_id: str) -> Optional[ScanSnapshot]:
        """Get specific scan by ID."""
        for snapshot in self.snapshots:
            if snapshot.scan_id == scan_id:
                return snapshot
        return None
    
    def get_score_trend(self) -> List[tuple]:
        """
        Get score trending over time.
        
        Returns:
            List of (timestamp, score) tuples
        """
        scans = self.get_all_scans()
        return [(s.timestamp, s.score.final_score) for s in scans]
    
    def get_improvement(self) -> Optional[int]:
        """
        Get total improvement from first to latest scan.
        
        Returns:
            Points improved (positive number) or None
        """
        scans = self.get_all_scans()
        if len(scans) < 2:
            return None
        
        first_score = scans[0].score.final_score
        latest_score = scans[-1].score.final_score
        
        return latest_score - first_score
    
    def get_comparison(self, scan_id_1: str, scan_id_2: str) -> Dict:
        """
        Compare two scans.
        
        Args:
            scan_id_1: First scan ID
            scan_id_2: Second scan ID
            
        Returns:
            Comparison dictionary
        """
        scan1 = self.get_scan_by_id(scan_id_1)
        scan2 = self.get_scan_by_id(scan_id_2)
        
        if not scan1 or not scan2:
            return {"error": "Scan not found"}
        
        return {
            "scan_1": {
                "id": scan1.scan_id,
                "score": scan1.score.final_score,
                "findings": scan1.total_findings
            },
            "scan_2": {
                "id": scan2.scan_id,
                "score": scan2.score.final_score,
                "findings": scan2.total_findings
            },
            "score_change": scan2.score.final_score - scan1.score.final_score,
            "findings_change": scan2.total_findings - scan1.total_findings
        }
    
    def print_timeline(self) -> None:
        """Print scan timeline."""
        scans = self.get_all_scans()
        
        if not scans:
            print("\n⏳ No scans recorded yet.\n")
            return
        
        print("\n" + "="*80)
        print("📅 SCAN HISTORY TIMELINE")
        print("="*80 + "\n")
        
        for i, scan in enumerate(scans, 1):
            print(f"{i}. {scan.scan_name}")
            print(f"   Time:      {scan.timestamp}")
            print(f"   Score:     {scan.score.final_score}/100  {scan.score.get_score_emoji()}")
            print(f"   Grade:     {scan.score.get_score_grade()}")
            print(f"   Findings:  {scan.total_findings}")
            
            # Show improvement from previous
            if i > 1:
                prev_score = scans[i-2].score.final_score
                change = scan.score.final_score - prev_score
                if change > 0:
                    print(f"   Change:    +{change} ↑ IMPROVING 🎉")
                elif change < 0:
                    print(f"   Change:    {change} ↓ DECLINING ⚠️")
                else:
                    print(f"   Change:    0 → STABLE")
            
            print()
        
        # Overall trend
        improvement = self.get_improvement()
        if improvement is not None:
            print(f"Overall Improvement: +{improvement} points over {len(scans)} scans\n")
        
        print("="*80 + "\n")
    
    def print_improvement_summary(self) -> None:
        """Print improvement summary."""
        scans = self.get_all_scans()
        
        if len(scans) < 2:
            print("\n⚠️  Need at least 2 scans to show improvement.\n")
            return
        
        first = scans[0]
        latest = scans[-1]
        improvement = self.get_improvement()
        
        first_critical = first.findings_by_severity['CRITICAL']
        latest_critical = latest.findings_by_severity['CRITICAL']
        
        first_high = first.findings_by_severity['HIGH']
        latest_high = latest.findings_by_severity['HIGH']
        
        print("\n" + "="*80)
        print("🏆 IMPROVEMENT SUMMARY")
        print("="*80 + "\n")
        
        print(f"From: {first.scan_name} ({first.timestamp})")
        print(f"To:   {latest.scan_name} ({latest.timestamp})\n")
        
        print(f"Security Score:")
        print(f"  Before: {first.score.final_score}/100 ({first.score.get_score_grade()})")
        print(f"  After:  {latest.score.final_score}/100 ({latest.score.get_score_grade()})")
        print(f"  Change: +{improvement} points ↑\n")
        
        print(f"Critical Issues:")
        print(f"  Before: {first_critical}")
        print(f"  After:  {latest_critical}")
        print(f"  Fixed:  {first_critical - latest_critical} 🎯\n")
        
        print(f"High Issues:")
        print(f"  Before: {first_high}")
        print(f"  After:  {latest_high}")
        print(f"  Fixed:  {first_high - latest_high} 🎯\n")
        
        print(f"Total Findings:")
        print(f"  Before: {first.total_findings}")
        print(f"  After:  {latest.total_findings}")
        print(f"  Fixed:  {first.total_findings - latest.total_findings} 🎯")
        
        print("\n" + "="*80 + "\n")
    
    def export_csv(self, filename: str) -> None:
        """
        Export scan history to CSV for Excel/charts.
        
        Args:
            filename: Output CSV filename
        """
        import csv
        
        scans = self.get_all_scans()
        
        if not scans:
            print("No scans to export.")
            return
        
        with open(filename, 'w', newline='') as f:
            writer = csv.writer(f)
            
            # Header
            writer.writerow(['Timestamp', 'Score', 'Grade', 'Total Findings', 'Critical', 'High', 'Medium', 'Low'])
            
            # Data rows
            for scan in scans:
                writer.writerow([
                    scan.timestamp,
                    scan.score.final_score,
                    scan.score.get_score_grade(),
                    scan.total_findings,
                    scan.findings_by_severity['CRITICAL'],
                    scan.findings_by_severity['HIGH'],
                    scan.findings_by_severity['MEDIUM'],
                    scan.findings_by_severity['LOW']
                ])
        
        print(f"✅ History exported to: {filename}")
    
    def __len__(self) -> int:
        """Return number of scans."""
        return len(self.snapshots)