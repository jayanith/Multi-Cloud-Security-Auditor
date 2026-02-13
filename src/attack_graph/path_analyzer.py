"""
Attack Path Graph Module
Models attack scenarios as a directed graph and prioritizes risk paths
"""

class AttackPathGraph:
    def __init__(self):
        self.nodes = {}  # resource_id -> {type, name, findings}
        self.edges = []  # {from, to, attack_type, risk_score}
        self.attack_paths = []
    
    def build_graph(self, findings):
        """Build attack graph from scan findings"""
        # Create nodes for each vulnerable resource
        for finding in findings:
            resource = finding['resource']
            if resource not in self.nodes:
                self.nodes[resource] = {
                    'type': self._get_resource_type(finding),
                    'name': resource,
                    'findings': [],
                    'internet_exposed': self._is_internet_exposed(finding)
                }
            self.nodes[resource]['findings'].append(finding)
        
        # Create edges based on attack relationships
        self._build_attack_edges(findings)
        
        # Generate attack paths
        self._generate_attack_paths()
        
        return self.get_graph_data()
    
    def _get_resource_type(self, finding):
        """Extract resource type from finding"""
        resource = finding['resource']
        if 'bucket' in resource.lower() or finding['type'].startswith('S3_'):
            return 'S3'
        elif 'sg-' in resource or finding['type'].startswith('SG_'):
            return 'SecurityGroup'
        elif finding['type'].startswith('IAM_'):
            return 'IAM'
        return 'Unknown'
    
    def _is_internet_exposed(self, finding):
        """Check if resource is internet-exposed"""
        exposed_types = ['S3_PUBLIC_BUCKET', 'SG_OPEN_SSH', 'SG_OPEN_RDP', 
                        'SG_OPEN_DATABASE', 'SG_ALL_TRAFFIC']
        return finding['type'] in exposed_types
    
    def _build_attack_edges(self, findings):
        """Create edges representing attack paths"""
        # S3 public bucket -> Data exfiltration
        for resource, node in self.nodes.items():
            if node['type'] == 'S3':
                for finding in node['findings']:
                    if 'PUBLIC' in finding['type']:
                        self.edges.append({
                            'from': 'Internet',
                            'to': resource,
                            'attack_type': 'Data Exfiltration',
                            'risk_score': self._calculate_edge_risk(finding)
                        })
            
            # Open security group -> Lateral movement
            elif node['type'] == 'SecurityGroup':
                for finding in node['findings']:
                    if 'OPEN' in finding['type']:
                        self.edges.append({
                            'from': 'Internet',
                            'to': resource,
                            'attack_type': 'Initial Access',
                            'risk_score': self._calculate_edge_risk(finding)
                        })
            
            # IAM misconfig -> Privilege escalation
            elif node['type'] == 'IAM':
                for finding in node['findings']:
                    if 'ADMIN' in finding['type'] or 'WILDCARD' in finding['type']:
                        self.edges.append({
                            'from': resource,
                            'to': 'AWS Account',
                            'attack_type': 'Privilege Escalation',
                            'risk_score': self._calculate_edge_risk(finding)
                        })
    
    def _calculate_edge_risk(self, finding):
        """Calculate risk score for an attack edge"""
        base_score = {
            'CRITICAL': 10,
            'HIGH': 7,
            'MEDIUM': 4,
            'LOW': 2
        }.get(finding['severity'], 1)
        
        # Increase score for internet-exposed resources
        if self._is_internet_exposed(finding):
            base_score *= 1.5
        
        return round(base_score, 1)
    
    def _generate_attack_paths(self):
        """Generate complete attack paths from graph"""
        # Find paths starting from Internet
        internet_edges = [e for e in self.edges if e['from'] == 'Internet']
        
        for edge in internet_edges:
            path = {
                'name': f"{edge['attack_type']} via {edge['to']}",
                'steps': [edge['from'], edge['to']],
                'attack_types': [edge['attack_type']],
                'total_risk': edge['risk_score'],
                'severity': self._risk_to_severity(edge['risk_score']),
                'description': f"Attacker can perform {edge['attack_type']} through {edge['to']}"
            }
            
            # Check for chained attacks
            next_edges = [e for e in self.edges if e['from'] == edge['to']]
            for next_edge in next_edges:
                path['steps'].append(next_edge['to'])
                path['attack_types'].append(next_edge['attack_type'])
                path['total_risk'] += next_edge['risk_score']
                path['severity'] = self._risk_to_severity(path['total_risk'])
                path['description'] += f" → {next_edge['attack_type']} to {next_edge['to']}"
            
            self.attack_paths.append(path)
        
        # Sort by risk score
        self.attack_paths.sort(key=lambda x: x['total_risk'], reverse=True)
    
    def _risk_to_severity(self, risk_score):
        """Convert risk score to severity level"""
        if risk_score >= 15:
            return 'CRITICAL'
        elif risk_score >= 10:
            return 'HIGH'
        elif risk_score >= 5:
            return 'MEDIUM'
        return 'LOW'
    
    def get_top_attack_paths(self, n=3):
        """Get top N most dangerous attack paths"""
        return self.attack_paths[:n]
    
    def get_graph_data(self):
        """Return structured graph data"""
        return {
            'nodes': self.nodes,
            'edges': self.edges,
            'attack_paths': self.attack_paths,
            'top_3_paths': self.get_top_attack_paths(3),
            'total_paths': len(self.attack_paths),
            'highest_risk': self.attack_paths[0]['total_risk'] if self.attack_paths else 0
        }
    
    def get_summary(self):
        """Get human-readable summary"""
        if not self.attack_paths:
            return "No attack paths detected. Environment appears secure."
        
        summary = f"⚠️ ATTACK PATH ANALYSIS (SIMULATED)\n\n"
        summary += f"Total Attack Paths: {len(self.attack_paths)}\n"
        summary += f"Highest Risk Score: {self.attack_paths[0]['total_risk']}\n\n"
        summary += "TOP 3 MOST DANGEROUS PATHS:\n\n"
        
        for i, path in enumerate(self.get_top_attack_paths(3), 1):
            summary += f"{i}. {path['name']}\n"
            summary += f"   Risk Score: {path['total_risk']} ({path['severity']})\n"
            summary += f"   Path: {' → '.join(path['steps'])}\n"
            summary += f"   Description: {path['description']}\n\n"
        
        return summary
