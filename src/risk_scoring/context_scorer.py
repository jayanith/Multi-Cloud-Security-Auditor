"""
Context-Aware Risk Scoring Module
Calculates risk scores based on multiple factors
"""

class ContextAwareRiskScorer:
    def __init__(self):
        self.severity_weights = {
            'CRITICAL': 10,
            'HIGH': 7,
            'MEDIUM': 4,
            'LOW': 2
        }
    
    def calculate_risk_score(self, finding, attack_path_count=0):
        """Calculate context-aware risk score for a finding"""
        # Base severity score
        base_score = self.severity_weights.get(finding['severity'], 1)
        
        # Internet exposure multiplier
        exposure_multiplier = 1.0
        if self._is_internet_exposed(finding):
            exposure_multiplier = 1.8
        
        # Privilege level multiplier
        privilege_multiplier = 1.0
        if self._is_high_privilege(finding):
            privilege_multiplier = 1.5
        
        # Attack path multiplier (more paths = higher risk)
        path_multiplier = 1.0 + (attack_path_count * 0.2)
        
        # Calculate final score
        final_score = base_score * exposure_multiplier * privilege_multiplier * path_multiplier
        
        return {
            'total_score': round(final_score, 2),
            'base_score': base_score,
            'exposure_multiplier': exposure_multiplier,
            'privilege_multiplier': privilege_multiplier,
            'path_multiplier': path_multiplier,
            'explanation': self._explain_score(
                base_score, exposure_multiplier, 
                privilege_multiplier, path_multiplier
            )
        }
    
    def _is_internet_exposed(self, finding):
        """Check if finding involves internet exposure"""
        exposed_keywords = ['PUBLIC', 'OPEN', '0.0.0.0/0', 'AllUsers']
        finding_str = str(finding).upper()
        return any(keyword in finding_str for keyword in exposed_keywords)
    
    def _is_high_privilege(self, finding):
        """Check if finding involves high privileges"""
        privilege_keywords = ['ADMIN', 'ROOT', 'WILDCARD', '*', 'FULL_ACCESS']
        finding_str = str(finding).upper()
        return any(keyword in finding_str for keyword in privilege_keywords)
    
    def _explain_score(self, base, exposure, privilege, path):
        """Generate human-readable explanation of risk score"""
        explanation = []
        
        explanation.append(f"Base severity score: {base}")
        
        if exposure > 1.0:
            explanation.append(f"Internet-exposed (×{exposure})")
        
        if privilege > 1.0:
            explanation.append(f"High privilege level (×{privilege})")
        
        if path > 1.0:
            explanation.append(f"Used in {int((path - 1) / 0.2)} attack paths (×{path:.1f})")
        
        return " | ".join(explanation)
    
    def score_all_findings(self, findings, attack_graph_data=None):
        """Score all findings with context"""
        scored_findings = []
        
        # Count how many attack paths use each finding
        path_counts = {}
        if attack_graph_data:
            for path in attack_graph_data.get('attack_paths', []):
                for step in path.get('steps', []):
                    path_counts[step] = path_counts.get(step, 0) + 1
        
        for finding in findings:
            resource = finding['resource']
            path_count = path_counts.get(resource, 0)
            
            risk_data = self.calculate_risk_score(finding, path_count)
            
            scored_finding = finding.copy()
            scored_finding['risk_score'] = risk_data['total_score']
            scored_finding['risk_explanation'] = risk_data['explanation']
            scored_findings.append(scored_finding)
        
        # Sort by risk score
        scored_findings.sort(key=lambda x: x['risk_score'], reverse=True)
        
        return scored_findings
