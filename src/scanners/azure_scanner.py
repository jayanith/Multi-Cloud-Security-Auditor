"""
Azure Security Scanner
Detects misconfigurations in Azure resources
Requires: Reader role or Security Reader role
"""
from azure.identity import DefaultAzureCredential
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.resource.subscriptions import SubscriptionClient
from azure.core.exceptions import AzureError
from core.config import AZURE_RULES

class AzureScanner:
    def __init__(self, logger, subscription_id=None):
        self.logger = logger
        self.findings = []
        
        try:
            self.credential = DefaultAzureCredential()
            
            # Get subscription ID if not provided
            if not subscription_id:
                sub_client = SubscriptionClient(self.credential)
                subs = list(sub_client.subscriptions.list())
                if subs:
                    subscription_id = subs[0].subscription_id
                    self.logger.info(f"Using subscription: {subscription_id}")
                else:
                    raise Exception("No Azure subscriptions found")
            
            self.subscription_id = subscription_id
            self.storage_client = StorageManagementClient(self.credential, subscription_id)
            self.network_client = NetworkManagementClient(self.credential, subscription_id)
            
        except Exception as e:
            self.logger.error(f"Azure authentication failed: {e}")
            raise
    
    def verify_credentials(self):
        """Verify Azure credentials and permissions"""
        try:
            # Test by listing resource groups
            from azure.mgmt.resource import ResourceManagementClient
            resource_client = ResourceManagementClient(self.credential, self.subscription_id)
            list(resource_client.resource_groups.list())
            self.logger.success(f"Connected to Azure subscription: {self.subscription_id}")
            return True
        except AzureError as e:
            self.logger.error(f"Credential verification failed: {e}")
            return False
    
    def scan_storage_accounts(self):
        """Scan Azure Storage accounts for public access and encryption"""
        self.logger.info("Scanning Azure Storage accounts...")
        
        try:
            accounts = list(self.storage_client.storage_accounts.list())
            self.logger.info(f"Found {len(accounts)} storage accounts")
            
            for account in accounts:
                account_name = account.name
                resource_group = account.id.split('/')[4]
                
                # Check blob containers for public access
                try:
                    containers = self.storage_client.blob_containers.list(
                        resource_group, account_name
                    )
                    for container in containers:
                        if container.public_access and container.public_access != 'None':
                            self.add_finding('BLOB_PUBLIC_CONTAINER', 
                                           f"{account_name}/{container.name}",
                                           f"Container allows public {container.public_access} access")
                except Exception:
                    pass
                
                # Check encryption
                if not account.encryption or not account.encryption.services:
                    self.add_finding('STORAGE_NO_ENCRYPTION', account_name,
                                   f"Storage account lacks encryption configuration")
        
        except AzureError as e:
            self.logger.error(f"Storage scan failed: {e}")
    
    def scan_network_security_groups(self):
        """Scan Network Security Groups for overly permissive rules"""
        self.logger.info("Scanning Network Security Groups...")
        
        try:
            nsgs = list(self.network_client.network_security_groups.list_all())
            self.logger.info(f"Found {len(nsgs)} NSGs")
            
            for nsg in nsgs:
                nsg_name = nsg.name
                
                for rule in nsg.security_rules or []:
                    if rule.direction == 'Inbound' and rule.access == 'Allow':
                        # Check for internet-facing rules
                        source = rule.source_address_prefix or ''
                        if source in ['*', 'Internet', '0.0.0.0/0']:
                            dest_port = rule.destination_port_range or ''
                            
                            if '22' in str(dest_port) or dest_port == '*':
                                self.add_finding('NSG_OPEN_SSH', f"{nsg_name}/{rule.name}",
                                               f"Allows SSH (22) from Internet")
                            elif '3389' in str(dest_port) or dest_port == '*':
                                self.add_finding('NSG_OPEN_RDP', f"{nsg_name}/{rule.name}",
                                               f"Allows RDP (3389) from Internet")
        
        except AzureError as e:
            self.logger.error(f"NSG scan failed: {e}")
    
    def add_finding(self, finding_type, resource, details):
        """Add a security finding"""
        rule = AZURE_RULES.get(finding_type, {})
        finding = {
            'provider': 'Azure',
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
        """Execute full Azure security scan"""
        if not self.verify_credentials():
            return []
        
        self.scan_storage_accounts()
        self.scan_network_security_groups()
        
        return self.findings
