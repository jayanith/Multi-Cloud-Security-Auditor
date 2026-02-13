"""
AWS Security Scanner
Detects misconfigurations in AWS resources using boto3
Requires: SecurityAudit or ReadOnlyAccess IAM policy
"""
import boto3
from botocore.exceptions import ClientError, NoCredentialsError
from core.config import AWS_RULES

class AWSScanner:
    def __init__(self, logger, region='us-east-1'):
        self.logger = logger
        self.region = region
        self.findings = []
        
        try:
            self.s3 = boto3.client('s3', region_name=region)
            self.iam = boto3.client('iam', region_name=region)
            self.ec2 = boto3.client('ec2', region_name=region)
            self.sts = boto3.client('sts', region_name=region)
        except NoCredentialsError:
            self.logger.error("AWS credentials not found. Configure AWS CLI or set environment variables.")
            raise
    
    def verify_credentials(self):
        """Verify AWS credentials and permissions"""
        try:
            identity = self.sts.get_caller_identity()
            self.logger.success(f"✓ Authenticated as: {identity['Arn']}")
            self.logger.info(f"Account ID: {identity['Account']}")
            return True
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'InvalidClientTokenId':
                self.logger.error("✗ INVALID ACCESS KEY - Credentials are incorrect or deleted")
            elif error_code == 'SignatureDoesNotMatch':
                self.logger.error("✗ INVALID SECRET KEY - Secret access key is incorrect")
            elif error_code == 'AccessDenied':
                self.logger.error("✗ ACCESS DENIED - Credentials lack required permissions")
            else:
                self.logger.error(f"✗ Authentication failed: {error_code}")
            return False
        except NoCredentialsError:
            self.logger.error("✗ NO CREDENTIALS - AWS credentials not found")
            return False
        except Exception as e:
            self.logger.error(f"✗ Connection failed: {str(e)}")
            return False
    
    def scan_s3_buckets(self):
        """Scan S3 buckets for public access and encryption"""
        self.logger.info("Scanning S3 buckets...")
        
        try:
            buckets = self.s3.list_buckets()['Buckets']
            self.logger.info(f"Found {len(buckets)} S3 buckets")
            
            if len(buckets) == 0:
                self.logger.info("No S3 buckets found in account")
                return
            
            for bucket in buckets:
                bucket_name = bucket['Name']
                self.logger.info(f"  Checking bucket: {bucket_name}")
                
                # Check Block Public Access settings
                try:
                    block_config = self.s3.get_public_access_block(Bucket=bucket_name)
                    config = block_config['PublicAccessBlockConfiguration']
                    if not all([config.get('BlockPublicAcls'), config.get('BlockPublicPolicy'),
                               config.get('IgnorePublicAcls'), config.get('RestrictPublicBuckets')]):
                        self.add_finding('S3_PUBLIC_BUCKET', bucket_name, 
                                       f"Block Public Access is not fully enabled")
                except ClientError as e:
                    if e.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
                        self.add_finding('S3_PUBLIC_BUCKET', bucket_name,
                                       f"No Block Public Access configuration (publicly accessible)")
                
                # Check ACL for public access
                try:
                    acl = self.s3.get_bucket_acl(Bucket=bucket_name)
                    for grant in acl['Grants']:
                        grantee = grant.get('Grantee', {})
                        uri = grantee.get('URI', '')
                        if 'AllUsers' in uri or 'AuthenticatedUsers' in uri:
                            self.add_finding('S3_PUBLIC_BUCKET', bucket_name, 
                                           f"Bucket ACL grants public access to {uri.split('/')[-1]}")
                except ClientError:
                    pass
                
                # Check bucket policy
                try:
                    policy_response = self.s3.get_bucket_policy(Bucket=bucket_name)
                    policy = policy_response['Policy']
                    if '"Principal":"*"' in policy or '"Principal":{"AWS":"*"}' in policy:
                        self.add_finding('S3_PUBLIC_BUCKET', bucket_name,
                                       f"Bucket policy allows public access (Principal: *)")
                except ClientError:
                    pass
                
                # Check encryption
                try:
                    self.s3.get_bucket_encryption(Bucket=bucket_name)
                except ClientError as e:
                    if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                        self.add_finding('S3_NO_ENCRYPTION', bucket_name,
                                       f"Bucket lacks server-side encryption")
                
                # Check versioning
                try:
                    versioning = self.s3.get_bucket_versioning(Bucket=bucket_name)
                    if versioning.get('Status') != 'Enabled':
                        self.add_finding('S3_NO_VERSIONING', bucket_name,
                                       f"Bucket versioning is not enabled")
                except ClientError:
                    pass
                
                # Check logging
                try:
                    logging = self.s3.get_bucket_logging(Bucket=bucket_name)
                    if 'LoggingEnabled' not in logging:
                        self.add_finding('S3_NO_LOGGING', bucket_name,
                                       f"Bucket access logging is not enabled")
                except ClientError:
                    pass
        
        except ClientError as e:
            self.logger.error(f"S3 scan failed: {e}")
    
    def scan_iam_policies(self):
        """Scan IAM users and policies for excessive permissions"""
        self.logger.info("Scanning IAM policies...")
        
        try:
            # Check users
            users = self.iam.list_users()['Users']
            self.logger.info(f"Found {len(users)} IAM users")
            
            if len(users) == 0:
                self.logger.info("No IAM users found in account")
            
            for user in users:
                user_name = user['UserName']
                self.logger.info(f"  Checking user: {user_name}")
                
                # Check for access keys
                try:
                    keys = self.iam.list_access_keys(UserName=user_name)['AccessKeyMetadata']
                    for key in keys:
                        # Check key age
                        from datetime import datetime, timezone
                        key_age = (datetime.now(timezone.utc) - key['CreateDate']).days
                        if key_age > 90:
                            self.add_finding('IAM_OLD_ACCESS_KEY', f"{user_name}/{key['AccessKeyId']}",
                                           f"Access key is {key_age} days old (>90 days)")
                except ClientError:
                    pass
                
                # Check MFA
                try:
                    mfa_devices = self.iam.list_mfa_devices(UserName=user_name)['MFADevices']
                    if len(mfa_devices) == 0:
                        # Check if user has console access
                        try:
                            self.iam.get_login_profile(UserName=user_name)
                            self.add_finding('IAM_NO_MFA', user_name,
                                           f"User has console access but no MFA enabled")
                        except ClientError:
                            pass
                except ClientError:
                    pass
                
                # Check attached policies
                attached = self.iam.list_attached_user_policies(UserName=user_name)
                for policy in attached['AttachedPolicies']:
                    policy_name = policy['PolicyName']
                    if 'AdministratorAccess' in policy_name or 'FullAccess' in policy_name:
                        self.add_finding('IAM_ADMIN_USER', user_name,
                                       f"User has {policy_name} policy attached")
                
                # Check inline policies
                inline = self.iam.list_user_policies(UserName=user_name)
                for policy_name in inline['PolicyNames']:
                    policy_doc = self.iam.get_user_policy(UserName=user_name, PolicyName=policy_name)
                    if self._has_wildcard_permissions(policy_doc['PolicyDocument']):
                        self.add_finding('IAM_WILDCARD_POLICY', f"{user_name}/{policy_name}",
                                       f"Inline policy contains wildcard (*) permissions")
            
            # Check password policy
            try:
                pwd_policy = self.iam.get_account_password_policy()['PasswordPolicy']
                if pwd_policy.get('MinimumPasswordLength', 0) < 14:
                    self.add_finding('IAM_WEAK_PASSWORD_POLICY', 'Account',
                                   f"Password policy requires only {pwd_policy.get('MinimumPasswordLength')} characters (recommended: 14+)")
                if not pwd_policy.get('RequireSymbols') or not pwd_policy.get('RequireNumbers'):
                    self.add_finding('IAM_WEAK_PASSWORD_POLICY', 'Account',
                                   f"Password policy does not require symbols and numbers")
            except ClientError as e:
                if e.response['Error']['Code'] == 'NoSuchEntity':
                    self.add_finding('IAM_NO_PASSWORD_POLICY', 'Account',
                                   f"No account password policy configured")
        
        except ClientError as e:
            self.logger.error(f"IAM scan failed: {e}")
    
    def scan_security_groups(self):
        """Scan EC2 security groups for overly permissive rules"""
        self.logger.info("Scanning Security Groups...")
        
        try:
            sgs = self.ec2.describe_security_groups()['SecurityGroups']
            self.logger.info(f"Found {len(sgs)} security groups")
            
            if len(sgs) == 0:
                self.logger.info("No security groups found")
                return
            
            for sg in sgs:
                sg_id = sg['GroupId']
                sg_name = sg['GroupName']
                
                # Check inbound rules
                for rule in sg.get('IpPermissions', []):
                    protocol = rule.get('IpProtocol', '-1')
                    from_port = rule.get('FromPort', 0)
                    to_port = rule.get('ToPort', 65535)
                    
                    for ip_range in rule.get('IpRanges', []):
                        cidr = ip_range.get('CidrIp')
                        
                        if cidr == '0.0.0.0/0':
                            # Critical ports
                            if from_port == 22 or to_port == 22:
                                self.add_finding('SG_OPEN_SSH', f"{sg_id} ({sg_name})",
                                               f"Allows SSH (22) from anywhere (0.0.0.0/0)")
                            elif from_port == 3389 or to_port == 3389:
                                self.add_finding('SG_OPEN_RDP', f"{sg_id} ({sg_name})",
                                               f"Allows RDP (3389) from anywhere (0.0.0.0/0)")
                            elif from_port == 3306 or to_port == 3306:
                                self.add_finding('SG_OPEN_DATABASE', f"{sg_id} ({sg_name})",
                                               f"Allows MySQL (3306) from anywhere (0.0.0.0/0)")
                            elif from_port == 5432 or to_port == 5432:
                                self.add_finding('SG_OPEN_DATABASE', f"{sg_id} ({sg_name})",
                                               f"Allows PostgreSQL (5432) from anywhere (0.0.0.0/0)")
                            elif from_port == 1433 or to_port == 1433:
                                self.add_finding('SG_OPEN_DATABASE', f"{sg_id} ({sg_name})",
                                               f"Allows MSSQL (1433) from anywhere (0.0.0.0/0)")
                            elif from_port == 27017 or to_port == 27017:
                                self.add_finding('SG_OPEN_DATABASE', f"{sg_id} ({sg_name})",
                                               f"Allows MongoDB (27017) from anywhere (0.0.0.0/0)")
                            elif protocol == '-1' or (from_port == 0 and to_port == 65535):
                                self.add_finding('SG_ALL_TRAFFIC', f"{sg_id} ({sg_name})",
                                               f"Allows ALL traffic from anywhere (0.0.0.0/0)")
                            elif to_port - from_port > 1000:
                                self.add_finding('SG_WIDE_PORT_RANGE', f"{sg_id} ({sg_name})",
                                               f"Allows wide port range {from_port}-{to_port} from 0.0.0.0/0")
        
        except ClientError as e:
            self.logger.error(f"Security Group scan failed: {e}")
    
    def _has_wildcard_permissions(self, policy_doc):
        """Check if policy contains wildcard permissions"""
        statements = policy_doc.get('Statement', [])
        for stmt in statements:
            if stmt.get('Effect') == 'Allow':
                actions = stmt.get('Action', [])
                resources = stmt.get('Resource', [])
                if isinstance(actions, str):
                    actions = [actions]
                if isinstance(resources, str):
                    resources = [resources]
                if '*' in actions or '*' in resources:
                    return True
        return False
    
    def add_finding(self, finding_type, resource, details):
        """Add a security finding"""
        rule = AWS_RULES.get(finding_type, {})
        finding = {
            'provider': 'AWS',
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
        """Execute full AWS security scan"""
        if not self.verify_credentials():
            self.logger.error("Scan aborted due to authentication failure")
            raise Exception("AWS authentication failed - check your credentials")
        
        self.scan_s3_buckets()
        self.scan_iam_policies()
        self.scan_security_groups()
        
        self.logger.info(f"Scan completed: {len(self.findings)} findings")
        return self.findings
