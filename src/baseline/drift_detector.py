"""
Baseline Drift Detection Module
Compares current scan with previous baseline to detect changes
"""
import json
import os
from datetime import datetime

class BaselineDriftDetector:
    def __init__(self, baseline_dir='baselines'):
        self.baseline_dir = baseline_dir
        os.makedirs(baseline_dir, exist_ok=True)
    
    def save_baseline(self, provider, findings):
        """Save current scan as baseline"""
        baseline_file = os.path.join(self.baseline_dir, f'{provider}_baseline.json')
        baseline_data = {
            'timestamp': datetime.now().isoformat(),
            'provider': provider,
            'findings': findings,
            'finding_count': len(findings)
        }
        
        with open(baseline_file, 'w') as f:
            json.dump(baseline_data, f, indent=2)
        
        return baseline_file
    
    def load_baseline(self, provider):
        """Load previous baseline"""
        baseline_file = os.path.join(self.baseline_dir, f'{provider}_baseline.json')
        
        if not os.path.exists(baseline_file):
            return None
        
        with open(baseline_file, 'r') as f:
            return json.load(f)
    
    def detect_drift(self, provider, current_findings):
        """Compare current findings with baseline"""
        baseline = self.load_baseline(provider)
        
        if not baseline:
            # First run - no baseline exists
            self.save_baseline(provider, current_findings)
            return {
                'has_baseline': False,
                'message': 'First scan - baseline created',
                'new_risks': [],
                'fixed_issues': [],
                'unchanged': [],
                'worsened': []
            }
        
        baseline_findings = baseline['findings']
        
        # Create finding signatures for comparison
        baseline_sigs = {self._get_signature(f): f for f in baseline_findings}
        current_sigs = {self._get_signature(f): f for f in current_findings}
        
        # Detect changes
        new_risks = []
        fixed_issues = []
        unchanged = []
        worsened = []
        
        # Find new risks
        for sig, finding in current_sigs.items():
            if sig not in baseline_sigs:
                new_risks.append(finding)
            else:
                # Check if severity worsened
                baseline_sev = baseline_sigs[sig]['severity']
                current_sev = finding['severity']
                if self._severity_rank(current_sev) > self._severity_rank(baseline_sev):
                    worsened.append({
                        'finding': finding,
                        'old_severity': baseline_sev,
                        'new_severity': current_sev
                    })
                else:
                    unchanged.append(finding)
        
        # Find fixed issues
        for sig, finding in baseline_sigs.items():
            if sig not in current_sigs:
                fixed_issues.append(finding)
        
        # Save new baseline
        self.save_baseline(provider, current_findings)
        
        return {
            'has_baseline': True,
            'baseline_date': baseline['timestamp'],
            'new_risks': new_risks,
            'fixed_issues': fixed_issues,
            'unchanged': unchanged,
            'worsened': worsened,
            'summary': self._generate_summary(new_risks, fixed_issues, worsened)
        }
    
    def _get_signature(self, finding):
        """Create unique signature for a finding"""
        return f"{finding['type']}:{finding['resource']}"
    
    def _severity_rank(self, severity):
        """Convert severity to numeric rank"""
        ranks = {'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4}
        return ranks.get(severity, 0)
    
    def _generate_summary(self, new_risks, fixed_issues, worsened):
        """Generate human-readable drift summary"""
        summary = "📊 BASELINE DRIFT ANALYSIS\n\n"
        
        if not new_risks and not fixed_issues and not worsened:
            summary += "✓ No changes detected since last scan\n"
            return summary
        
        if new_risks:
            summary += f"🔴 NEW RISKS: {len(new_risks)}\n"
            for risk in new_risks[:3]:  # Show top 3
                summary += f"   • [{risk['severity']}] {risk['resource']}\n"
            if len(new_risks) > 3:
                summary += f"   ... and {len(new_risks) - 3} more\n"
            summary += "\n"
        
        if fixed_issues:
            summary += f"✅ FIXED ISSUES: {len(fixed_issues)}\n"
            for issue in fixed_issues[:3]:
                summary += f"   • [{issue['severity']}] {issue['resource']}\n"
            if len(fixed_issues) > 3:
                summary += f"   ... and {len(fixed_issues) - 3} more\n"
            summary += "\n"
        
        if worsened:
            summary += f"⚠️ WORSENED: {len(worsened)}\n"
            for item in worsened:
                summary += f"   • {item['finding']['resource']}: {item['old_severity']} → {item['new_severity']}\n"
            summary += "\n"
        
        return summary
