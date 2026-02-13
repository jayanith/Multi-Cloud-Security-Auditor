"""
Attack Chain Simulator
IMPORTANT: This module simulates attack logic WITHOUT executing real attacks
All scenarios are theoretical and educational only
"""
from core.config import SEVERITY

class AttackChainSimulator:
    def __init__(self, logger):
        self.logger = logger
        self.attack_chains = []
    
    def simulate_attacks(self, findings):
        """
        Generate logical attack chains based on findings
        SIMULATION ONLY - No actual exploitation occurs
        """
        self.logger.info("Simulating attack chains (logic-based, non-destructive)...")
        
        # Group findings by type
        finding_map = {}
        for finding in findings:
            ftype = finding['type']
            if ftype not in finding_map:
                finding_map[ftype] = []
            finding_map[ftype].append(finding)
        
        # Simulate attack scenarios
        self._simulate_data_exfiltration(finding_map)
        self._simulate_privilege_escalation(finding_map)
        self._simulate_network_intrusion(finding_map)
        self._simulate_lateral_movement(finding_map)
        
        self.logger.info(f"Generated {len(self.attack_chains)} attack scenarios")
        return self.attack_chains
    
    def _simulate_data_exfiltration(self, finding_map):
        """Simulate data exfiltration through public storage"""
        public_storage = (
            finding_map.get('S3_PUBLIC_BUCKET', []) + 
            finding_map.get('BLOB_PUBLIC_CONTAINER', [])
        )
        
        for finding in public_storage:
            chain = {
                'chain_id': f"CHAIN-{len(self.attack_chains)+1}",
                'name': 'Public Storage Data Exfiltration',
                'severity': 'CRITICAL',
                'provider': finding['provider'],
                'steps': [
                    {
                        'step': 1,
                        'action': 'Reconnaissance',
                        'description': f"Attacker discovers public {finding['resource']}",
                        'technique': 'MITRE ATT&CK: T1580 - Cloud Infrastructure Discovery',
                        'simulated': True
                    },
                    {
                        'step': 2,
                        'action': 'Access',
                        'description': 'Attacker accesses bucket without authentication',
                        'technique': 'MITRE ATT&CK: T1530 - Data from Cloud Storage',
                        'simulated': True
                    },
                    {
                        'step': 3,
                        'action': 'Exfiltration',
                        'description': 'Attacker downloads sensitive data',
                        'technique': 'MITRE ATT&CK: T1537 - Transfer Data to Cloud Account',
                        'simulated': True
                    }
                ],
                'impact': {
                    'confidentiality': 'HIGH',
                    'integrity': 'LOW',
                    'availability': 'NONE',
                    'business_impact': 'Data breach, regulatory fines, reputation damage'
                },
                'likelihood': 'HIGH',
                'exploitability': 'TRIVIAL - No authentication required',
                'affected_resource': finding['resource'],
                'real_world_example': 'Capital One breach (2019) - Misconfigured S3 bucket',
                'disclaimer': 'SIMULATION ONLY - No actual data access performed'
            }
            self.attack_chains.append(chain)
    
    def _simulate_privilege_escalation(self, finding_map):
        """Simulate privilege escalation through IAM misconfigurations"""
        iam_issues = (
            finding_map.get('IAM_ADMIN_USER', []) + 
            finding_map.get('IAM_WILDCARD_POLICY', [])
        )
        
        for finding in iam_issues:
            chain = {
                'chain_id': f"CHAIN-{len(self.attack_chains)+1}",
                'name': 'IAM Privilege Escalation',
                'severity': 'CRITICAL',
                'provider': finding['provider'],
                'steps': [
                    {
                        'step': 1,
                        'action': 'Initial Access',
                        'description': f"Attacker compromises credentials for {finding['resource']}",
                        'technique': 'MITRE ATT&CK: T1078 - Valid Accounts',
                        'simulated': True
                    },
                    {
                        'step': 2,
                        'action': 'Privilege Escalation',
                        'description': 'Attacker leverages excessive permissions',
                        'technique': 'MITRE ATT&CK: T1098 - Account Manipulation',
                        'simulated': True
                    },
                    {
                        'step': 3,
                        'action': 'Persistence',
                        'description': 'Attacker creates backdoor admin accounts',
                        'technique': 'MITRE ATT&CK: T1136 - Create Account',
                        'simulated': True
                    },
                    {
                        'step': 4,
                        'action': 'Impact',
                        'description': 'Full account takeover achieved',
                        'technique': 'MITRE ATT&CK: T1531 - Account Access Removal',
                        'simulated': True
                    }
                ],
                'impact': {
                    'confidentiality': 'CRITICAL',
                    'integrity': 'CRITICAL',
                    'availability': 'CRITICAL',
                    'business_impact': 'Complete cloud environment compromise'
                },
                'likelihood': 'MEDIUM',
                'exploitability': 'Requires credential compromise first',
                'affected_resource': finding['resource'],
                'real_world_example': 'Tesla Kubernetes breach (2018) - Compromised credentials',
                'disclaimer': 'SIMULATION ONLY - No privilege escalation attempted'
            }
            self.attack_chains.append(chain)
    
    def _simulate_network_intrusion(self, finding_map):
        """Simulate network-based attacks through open security groups"""
        network_issues = (
            finding_map.get('SG_OPEN_SSH', []) + 
            finding_map.get('SG_OPEN_RDP', []) +
            finding_map.get('NSG_OPEN_SSH', []) +
            finding_map.get('NSG_OPEN_RDP', [])
        )
        
        for finding in network_issues:
            protocol = 'SSH' if 'SSH' in finding['type'] else 'RDP'
            port = '22' if protocol == 'SSH' else '3389'
            
            chain = {
                'chain_id': f"CHAIN-{len(self.attack_chains)+1}",
                'name': f'{protocol} Brute-Force Attack',
                'severity': 'HIGH',
                'provider': finding['provider'],
                'steps': [
                    {
                        'step': 1,
                        'action': 'Reconnaissance',
                        'description': f"Attacker scans and finds open port {port}",
                        'technique': 'MITRE ATT&CK: T1046 - Network Service Scanning',
                        'simulated': True
                    },
                    {
                        'step': 2,
                        'action': 'Brute Force',
                        'description': f"Attacker attempts {protocol} brute-force attack",
                        'technique': 'MITRE ATT&CK: T1110 - Brute Force',
                        'simulated': True
                    },
                    {
                        'step': 3,
                        'action': 'Initial Access',
                        'description': 'Attacker gains shell access',
                        'technique': 'MITRE ATT&CK: T1021 - Remote Services',
                        'simulated': True
                    },
                    {
                        'step': 4,
                        'action': 'Lateral Movement',
                        'description': 'Attacker pivots to other resources',
                        'technique': 'MITRE ATT&CK: T1570 - Lateral Tool Transfer',
                        'simulated': True
                    }
                ],
                'impact': {
                    'confidentiality': 'HIGH',
                    'integrity': 'HIGH',
                    'availability': 'MEDIUM',
                    'business_impact': 'Server compromise, data theft, ransomware'
                },
                'likelihood': 'MEDIUM',
                'exploitability': 'Requires weak credentials',
                'affected_resource': finding['resource'],
                'real_world_example': f'Automated {protocol} brute-force attacks occur millions of times daily',
                'disclaimer': 'SIMULATION ONLY - No brute-force attack performed'
            }
            self.attack_chains.append(chain)
    
    def _simulate_lateral_movement(self, finding_map):
        """Simulate lateral movement combining multiple vulnerabilities"""
        if len(finding_map) >= 2:
            # Multi-stage attack combining findings
            all_findings = []
            for findings in finding_map.values():
                all_findings.extend(findings)
            
            if len(all_findings) >= 2:
                chain = {
                    'chain_id': f"CHAIN-{len(self.attack_chains)+1}",
                    'name': 'Multi-Stage Attack Chain',
                    'severity': 'CRITICAL',
                    'provider': all_findings[0]['provider'],
                    'steps': [
                        {
                            'step': 1,
                            'action': 'Initial Compromise',
                            'description': f"Exploit {all_findings[0]['type']}",
                            'technique': 'MITRE ATT&CK: T1190 - Exploit Public-Facing Application',
                            'simulated': True
                        },
                        {
                            'step': 2,
                            'action': 'Credential Harvesting',
                            'description': 'Extract cloud credentials from compromised resource',
                            'technique': 'MITRE ATT&CK: T1552 - Unsecured Credentials',
                            'simulated': True
                        },
                        {
                            'step': 3,
                            'action': 'Lateral Movement',
                            'description': f"Use credentials to access {all_findings[1]['type']}",
                            'technique': 'MITRE ATT&CK: T1550 - Use Alternate Authentication Material',
                            'simulated': True
                        },
                        {
                            'step': 4,
                            'action': 'Objective',
                            'description': 'Achieve full environment compromise',
                            'technique': 'MITRE ATT&CK: T1485 - Data Destruction',
                            'simulated': True
                        }
                    ],
                    'impact': {
                        'confidentiality': 'CRITICAL',
                        'integrity': 'CRITICAL',
                        'availability': 'CRITICAL',
                        'business_impact': 'Complete infrastructure compromise'
                    },
                    'likelihood': 'MEDIUM',
                    'exploitability': 'Requires multiple vulnerabilities',
                    'affected_resource': 'Multiple resources',
                    'real_world_example': 'SolarWinds supply chain attack (2020)',
                    'disclaimer': 'SIMULATION ONLY - Theoretical attack path analysis'
                }
                self.attack_chains.append(chain)
    
    def calculate_risk_score(self):
        """Calculate overall risk score based on attack chains"""
        if not self.attack_chains:
            return 0
        
        severity_scores = {'CRITICAL': 10, 'HIGH': 7, 'MEDIUM': 4, 'LOW': 2}
        likelihood_scores = {'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
        
        total_score = 0
        for chain in self.attack_chains:
            severity = severity_scores.get(chain['severity'], 0)
            likelihood = likelihood_scores.get(chain['likelihood'], 1)
            total_score += severity * likelihood
        
        # Normalize to 0-100
        max_possible = len(self.attack_chains) * 10 * 3
        risk_score = min(100, int((total_score / max_possible) * 100)) if max_possible > 0 else 0
        
        return risk_score
