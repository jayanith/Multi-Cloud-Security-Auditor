"""
GCP Security Scanner
Detects misconfigurations in Google Cloud Platform
Requires: Security Reviewer role
"""
from google.cloud import storage, compute_v1
from google.oauth2 import service_account
from core.config import SEVERITY

GCP_RULES = {
    'GCS_PUBLIC_BUCKET': {
        'severity': 'CRITICAL',
        'category': 'Data Exposure',
        'description': 'GCS bucket allows public access',
        'cwe': 'CWE-732',
        'attack_vector': 'Direct data exfiltration'
    },
    'GCS_NO_ENCRYPTION': {
        'severity': 'HIGH',
        'category': 'Encryption',
        'description': 'GCS bucket lacks encryption',
        'cwe': 'CWE-311',
        'attack_vector': 'Data interception'
    },
    'FIREWALL_OPEN_SSH': {
        'severity': 'HIGH',
        'category': 'Network Exposure',
        'description': 'Firewall allows SSH from 0.0.0.0/0',
        'cwe': 'CWE-284',
        'attack_vector': 'Brute-force attack'
    },
    'FIREWALL_OPEN_RDP': {
        'severity': 'HIGH',
        'category': 'Network Exposure',
        'description': 'Firewall allows RDP from 0.0.0.0/0',
        'cwe': 'CWE-284',
        'attack_vector': 'Brute-force attack'
    }
}

class GCPScanner:
    def __init__(self, logger, project_id=None, credentials_file=None):
        self.logger = logger
        self.project_id = project_id
        self.findings = []
        
        try:
            if credentials_file:
                credentials = service_account.Credentials.from_service_account_file(credentials_file)
                self.storage_client = storage.Client(credentials=credentials, project=project_id)
                self.compute_client = compute_v1.FirewallsClient(credentials=credentials)
            else:
                self.storage_client = storage.Client(project=project_id)
                self.compute_client = compute_v1.FirewallsClient()
        except Exception as e:
            self.logger.error(f"GCP authentication failed: {e}")
            raise
    
    def verify_credentials(self):
        """Verify GCP credentials"""
        try:
            list(self.storage_client.list_buckets(max_results=1))
            self.logger.success(f"Connected to GCP project: {self.project_id}")
            return True
        except Exception as e:
            self.logger.error(f"Credential verification failed: {e}")
            return False
    
    def scan_gcs_buckets(self):
        """Scan GCS buckets for public access and encryption"""
        self.logger.info("Scanning GCS buckets...")
        
        try:
            buckets = list(self.storage_client.list_buckets())
            self.logger.info(f"Found {len(buckets)} GCS buckets")
            
            for bucket in buckets:
                # Check public access
                iam_policy = bucket.get_iam_policy()
                for binding in iam_policy.bindings:
                    if 'allUsers' in binding.get('members', []) or 'allAuthenticatedUsers' in binding.get('members', []):
                        self.add_finding('GCS_PUBLIC_BUCKET', bucket.name,
                                       f"Bucket allows public access")
                        break
                
                # Check encryption
                if not bucket.default_kms_key_name:
                    self.add_finding('GCS_NO_ENCRYPTION', bucket.name,
                                   f"Bucket lacks customer-managed encryption")
        
        except Exception as e:
            self.logger.error(f"GCS scan failed: {e}")
    
    def scan_firewall_rules(self):
        """Scan VPC firewall rules for overly permissive access"""
        self.logger.info("Scanning firewall rules...")
        
        try:
            request = compute_v1.ListFirewallsRequest(project=self.project_id)
            firewalls = self.compute_client.list(request=request)
            
            count = 0
            for firewall in firewalls:
                count += 1
                if firewall.direction == 'INGRESS' and firewall.source_ranges:
                    if '0.0.0.0/0' in firewall.source_ranges:
                        for allowed in firewall.allowed:
                            if allowed.I_p_protocol == 'tcp':
                                if '22' in allowed.ports or not allowed.ports:
                                    self.add_finding('FIREWALL_OPEN_SSH', firewall.name,
                                                   f"Allows SSH from 0.0.0.0/0")
                                if '3389' in allowed.ports or not allowed.ports:
                                    self.add_finding('FIREWALL_OPEN_RDP', firewall.name,
                                                   f"Allows RDP from 0.0.0.0/0")
            
            self.logger.info(f"Found {count} firewall rules")
        
        except Exception as e:
            self.logger.error(f"Firewall scan failed: {e}")
    
    def add_finding(self, finding_type, resource, details):
        """Add a security finding"""
        rule = GCP_RULES.get(finding_type, {})
        finding = {
            'provider': 'GCP',
            'type': finding_type,
            'resource': resource,
            'severity': rule.get('severity', 'MEDIUM'),
            'category': rule.get('category', 'Security'),
            'description': rule.get('description', details),
            'details': details,
            'cwe': rule.get('cwe', ''),
            'attack_vector': rule.get('attack_vector', '')
        }
        self.findings.append(finding)
        self.logger.finding(finding['severity'], resource, details)
    
    def run_scan(self):
        """Execute full GCP security scan"""
        if not self.verify_credentials():
            return []
        
        self.scan_gcs_buckets()
        self.scan_firewall_rules()
        
        return self.findings
