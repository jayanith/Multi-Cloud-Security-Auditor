"""
Auto-Remediation Template Generator
Generates actionable remediation steps for detected vulnerabilities
"""

class RemediationGenerator:
    def __init__(self, logger):
        self.logger = logger
    
    def generate_remediation(self, findings):
        """Generate remediation templates for all findings"""
        self.logger.info("Generating remediation templates...")
        
        remediations = []
        for finding in findings:
            remediation = self._get_remediation_template(finding)
            if remediation:
                remediations.append(remediation)
        
        return remediations
    
    def _get_remediation_template(self, finding):
        """Get remediation template for specific finding type"""
        templates = {
            'S3_PUBLIC_BUCKET': self._remediate_s3_public,
            'S3_NO_ENCRYPTION': self._remediate_s3_encryption,
            'IAM_ADMIN_USER': self._remediate_iam_admin,
            'IAM_WILDCARD_POLICY': self._remediate_iam_wildcard,
            'SG_OPEN_SSH': self._remediate_sg_ssh,
            'SG_OPEN_RDP': self._remediate_sg_rdp,
            'SG_ALL_TRAFFIC': self._remediate_sg_all,
            'BLOB_PUBLIC_CONTAINER': self._remediate_blob_public,
            'NSG_OPEN_SSH': self._remediate_nsg_ssh,
            'NSG_OPEN_RDP': self._remediate_nsg_rdp,
            'STORAGE_NO_ENCRYPTION': self._remediate_storage_encryption
        }
        
        template_func = templates.get(finding['type'])
        if template_func:
            return template_func(finding)
        return None
    
    def _remediate_s3_public(self, finding):
        bucket = finding['resource']
        return {
            'finding_id': finding['type'],
            'resource': bucket,
            'priority': 'CRITICAL',
            'remediation_steps': [
                '1. Review bucket contents to ensure no sensitive data is exposed',
                '2. Remove public access via ACL',
                '3. Update bucket policy to restrict access',
                '4. Enable S3 Block Public Access'
            ],
            'aws_cli': f'''# Block public access
aws s3api put-public-access-block \\
    --bucket {bucket} \\
    --public-access-block-configuration \\
    "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"

# Remove public ACL
aws s3api put-bucket-acl --bucket {bucket} --acl private''',
            'terraform': f'''resource "aws_s3_bucket_public_access_block" "{bucket.replace('-', '_')}" {{
  bucket = "{bucket}"
  
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}}''',
            'prevention': 'Use AWS Organizations SCPs to prevent public S3 buckets',
            'references': [
                'https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html'
            ]
        }
    
    def _remediate_s3_encryption(self, finding):
        bucket = finding['resource']
        return {
            'finding_id': finding['type'],
            'resource': bucket,
            'priority': 'HIGH',
            'remediation_steps': [
                '1. Enable default encryption on S3 bucket',
                '2. Choose AES-256 (SSE-S3) or AWS KMS (SSE-KMS)',
                '3. Verify encryption is applied to new objects'
            ],
            'aws_cli': f'''# Enable AES-256 encryption
aws s3api put-bucket-encryption \\
    --bucket {bucket} \\
    --server-side-encryption-configuration '{{
        "Rules": [{{
            "ApplyServerSideEncryptionByDefault": {{
                "SSEAlgorithm": "AES256"
            }},
            "BucketKeyEnabled": true
        }}]
    }}'

# Or use KMS encryption
aws s3api put-bucket-encryption \\
    --bucket {bucket} \\
    --server-side-encryption-configuration '{{
        "Rules": [{{
            "ApplyServerSideEncryptionByDefault": {{
                "SSEAlgorithm": "aws:kms",
                "KMSMasterKeyID": "your-kms-key-id"
            }},
            "BucketKeyEnabled": true
        }}]
    }}'
''',
            'terraform': f'''resource "aws_s3_bucket_server_side_encryption_configuration" "{bucket.replace('-', '_')}" {{
  bucket = "{bucket}"
  
  rule {{
    apply_server_side_encryption_by_default {{
      sse_algorithm = "AES256"
    }}
    bucket_key_enabled = true
  }}
}}''',
            'prevention': 'Enable encryption by default in AWS Config rules',
            'references': [
                'https://docs.aws.amazon.com/AmazonS3/latest/userguide/default-bucket-encryption.html'
            ]
        }
    
    def _remediate_iam_admin(self, finding):
        user = finding['resource']
        return {
            'finding_id': finding['type'],
            'resource': user,
            'priority': 'CRITICAL',
            'remediation_steps': [
                '1. Review user\'s actual permission requirements',
                '2. Create custom policy with least-privilege permissions',
                '3. Detach AdministratorAccess policy',
                '4. Attach new least-privilege policy',
                '5. Test to ensure user can still perform required tasks'
            ],
            'aws_cli': f'''# Detach admin policy
aws iam detach-user-policy \\
    --user-name {user} \\
    --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# Create and attach least-privilege policy
aws iam create-policy \\
    --policy-name {user}-LeastPrivilege \\
    --policy-document file://least-privilege-policy.json

aws iam attach-user-policy \\
    --user-name {user} \\
    --policy-arn arn:aws:iam::ACCOUNT_ID:policy/{user}-LeastPrivilege''',
            'policy_example': '''{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:PutObject"
      ],
      "Resource": "arn:aws:s3:::specific-bucket/*"
    }
  ]
}''',
            'prevention': 'Use IAM Access Analyzer to identify unused permissions',
            'references': [
                'https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html'
            ]
        }
    
    def _remediate_iam_wildcard(self, finding):
        return {
            'finding_id': finding['type'],
            'resource': finding['resource'],
            'priority': 'HIGH',
            'remediation_steps': [
                '1. Identify specific actions and resources needed',
                '2. Replace wildcard (*) with explicit permissions',
                '3. Use IAM policy simulator to test',
                '4. Apply principle of least privilege'
            ],
            'aws_cli': '''# Review policy
aws iam get-user-policy --user-name USERNAME --policy-name POLICY_NAME

# Update with specific permissions
aws iam put-user-policy --user-name USERNAME --policy-name POLICY_NAME --policy-document file://specific-policy.json''',
            'policy_example': '''{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeInstances",
        "ec2:StartInstances",
        "ec2:StopInstances"
      ],
      "Resource": "arn:aws:ec2:region:account:instance/specific-instance-id"
    }
  ]
}''',
            'prevention': 'Implement automated policy validation in CI/CD',
            'references': [
                'https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies.html'
            ]
        }
    
    def _remediate_sg_ssh(self, finding):
        sg_id = finding['resource'].split()[0]
        return {
            'finding_id': finding['type'],
            'resource': sg_id,
            'priority': 'HIGH',
            'remediation_steps': [
                '1. Identify legitimate IP addresses that need SSH access',
                '2. Remove 0.0.0.0/0 rule',
                '3. Add specific IP ranges or use VPN/bastion host',
                '4. Consider using AWS Systems Manager Session Manager instead'
            ],
            'aws_cli': f'''# Remove public SSH access
aws ec2 revoke-security-group-ingress \\
    --group-id {sg_id} \\
    --protocol tcp \\
    --port 22 \\
    --cidr 0.0.0.0/0

# Add specific IP range
aws ec2 authorize-security-group-ingress \\
    --group-id {sg_id} \\
    --protocol tcp \\
    --port 22 \\
    --cidr YOUR_IP/32''',
            'terraform': f'''resource "aws_security_group_rule" "ssh_restricted" {{
  type              = "ingress"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = ["YOUR_IP/32"]  # Replace with your IP
  security_group_id = "{sg_id}"
}}''',
            'prevention': 'Use AWS Systems Manager Session Manager for SSH-less access',
            'references': [
                'https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager.html'
            ]
        }
    
    def _remediate_sg_rdp(self, finding):
        sg_id = finding['resource'].split()[0]
        return {
            'finding_id': finding['type'],
            'resource': sg_id,
            'priority': 'HIGH',
            'remediation_steps': [
                '1. Identify legitimate IP addresses that need RDP access',
                '2. Remove 0.0.0.0/0 rule',
                '3. Add specific IP ranges or use VPN',
                '4. Enable Network Level Authentication (NLA)'
            ],
            'aws_cli': f'''# Remove public RDP access
aws ec2 revoke-security-group-ingress \\
    --group-id {sg_id} \\
    --protocol tcp \\
    --port 3389 \\
    --cidr 0.0.0.0/0

# Add specific IP range
aws ec2 authorize-security-group-ingress \\
    --group-id {sg_id} \\
    --protocol tcp \\
    --port 3389 \\
    --cidr YOUR_IP/32''',
            'prevention': 'Use AWS Client VPN or bastion host architecture',
            'references': [
                'https://docs.aws.amazon.com/vpn/latest/clientvpn-admin/what-is.html'
            ]
        }
    
    def _remediate_sg_all(self, finding):
        sg_id = finding['resource'].split()[0]
        return {
            'finding_id': finding['type'],
            'resource': sg_id,
            'priority': 'CRITICAL',
            'remediation_steps': [
                '1. IMMEDIATELY remove the 0.0.0.0/0 all traffic rule',
                '2. Identify required ports and protocols',
                '3. Add specific rules for each service',
                '4. Use principle of least privilege'
            ],
            'aws_cli': f'''# Remove all traffic rule
aws ec2 revoke-security-group-ingress \\
    --group-id {sg_id} \\
    --ip-permissions IpProtocol=-1,IpRanges='[{{CidrIp=0.0.0.0/0}}]'

# Add specific rules (example: HTTPS only)
aws ec2 authorize-security-group-ingress \\
    --group-id {sg_id} \\
    --protocol tcp \\
    --port 443 \\
    --cidr 0.0.0.0/0''',
            'prevention': 'Implement AWS Config rule to detect and alert on overly permissive SGs',
            'references': [
                'https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html'
            ]
        }
    
    def _remediate_blob_public(self, finding):
        resource_parts = finding['resource'].split('/')
        account = resource_parts[0] if len(resource_parts) > 0 else 'ACCOUNT'
        container = resource_parts[1] if len(resource_parts) > 1 else 'CONTAINER'
        
        return {
            'finding_id': finding['type'],
            'resource': finding['resource'],
            'priority': 'CRITICAL',
            'remediation_steps': [
                '1. Review container contents for sensitive data',
                '2. Disable public access on container',
                '3. Use SAS tokens for controlled access',
                '4. Enable Azure Storage firewall'
            ],
            'azure_cli': f'''# Disable public access
az storage container set-permission \\
    --name {container} \\
    --account-name {account} \\
    --public-access off

# Generate SAS token for controlled access
az storage container generate-sas \\
    --name {container} \\
    --account-name {account} \\
    --permissions r \\
    --expiry 2024-12-31''',
            'prevention': 'Use Azure Policy to prevent public blob containers',
            'references': [
                'https://docs.microsoft.com/en-us/azure/storage/blobs/anonymous-read-access-prevent'
            ]
        }
    
    def _remediate_nsg_ssh(self, finding):
        return {
            'finding_id': finding['type'],
            'resource': finding['resource'],
            'priority': 'HIGH',
            'remediation_steps': [
                '1. Identify legitimate source IPs',
                '2. Update NSG rule to restrict source',
                '3. Consider using Azure Bastion',
                '4. Enable Just-In-Time VM access'
            ],
            'azure_cli': '''# Update NSG rule
az network nsg rule update \\
    --resource-group RESOURCE_GROUP \\
    --nsg-name NSG_NAME \\
    --name RULE_NAME \\
    --source-address-prefixes YOUR_IP/32

# Or delete and recreate with specific IP
az network nsg rule delete \\
    --resource-group RESOURCE_GROUP \\
    --nsg-name NSG_NAME \\
    --name RULE_NAME''',
            'prevention': 'Use Azure Bastion for secure RDP/SSH access',
            'references': [
                'https://docs.microsoft.com/en-us/azure/bastion/bastion-overview'
            ]
        }
    
    def _remediate_nsg_rdp(self, finding):
        return {
            'finding_id': finding['type'],
            'resource': finding['resource'],
            'priority': 'HIGH',
            'remediation_steps': [
                '1. Identify legitimate source IPs',
                '2. Update NSG rule to restrict source',
                '3. Use Azure Bastion for RDP access',
                '4. Enable MFA for RDP sessions'
            ],
            'azure_cli': '''# Update NSG rule
az network nsg rule update \\
    --resource-group RESOURCE_GROUP \\
    --nsg-name NSG_NAME \\
    --name RULE_NAME \\
    --source-address-prefixes YOUR_IP/32''',
            'prevention': 'Implement Just-In-Time VM access in Azure Security Center',
            'references': [
                'https://docs.microsoft.com/en-us/azure/security-center/security-center-just-in-time'
            ]
        }
    
    def _remediate_storage_encryption(self, finding):
        return {
            'finding_id': finding['type'],
            'resource': finding['resource'],
            'priority': 'HIGH',
            'remediation_steps': [
                '1. Enable encryption for storage account',
                '2. Choose Microsoft-managed or customer-managed keys',
                '3. Verify encryption is applied'
            ],
            'azure_cli': f'''# Enable encryption (enabled by default on new accounts)
az storage account update \\
    --name {finding['resource']} \\
    --resource-group RESOURCE_GROUP \\
    --encryption-services blob file

# Use customer-managed key
az storage account update \\
    --name {finding['resource']} \\
    --resource-group RESOURCE_GROUP \\
    --encryption-key-source Microsoft.Keyvault \\
    --encryption-key-vault KEY_VAULT_URI \\
    --encryption-key-name KEY_NAME''',
            'prevention': 'Azure Storage encryption is enabled by default for new accounts',
            'references': [
                'https://docs.microsoft.com/en-us/azure/storage/common/storage-service-encryption'
            ]
        }
