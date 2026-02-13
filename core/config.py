"""
Core Configuration and Security Rules
Defines detection rules, severity levels, and scanning parameters
"""

# Severity levels
SEVERITY = {
    'CRITICAL': 4,
    'HIGH': 3,
    'MEDIUM': 2,
    'LOW': 1,
    'INFO': 0
}

# AWS Security Rules
AWS_RULES = {
    'S3_PUBLIC_BUCKET': {
        'severity': 'CRITICAL',
        'category': 'Data Exposure',
        'description': 'S3 bucket allows public read/write access',
        'cwe': 'CWE-732',
        'attack_vector': 'Direct data exfiltration'
    },
    'S3_NO_ENCRYPTION': {
        'severity': 'HIGH',
        'category': 'Encryption',
        'description': 'S3 bucket lacks server-side encryption',
        'cwe': 'CWE-311',
        'attack_vector': 'Data interception'
    },
    'S3_NO_VERSIONING': {
        'severity': 'MEDIUM',
        'category': 'Data Protection',
        'description': 'S3 bucket versioning is not enabled',
        'cwe': 'CWE-404',
        'attack_vector': 'Data loss/ransomware'
    },
    'S3_NO_LOGGING': {
        'severity': 'MEDIUM',
        'category': 'Logging',
        'description': 'S3 bucket access logging is not enabled',
        'cwe': 'CWE-778',
        'attack_vector': 'Undetected access'
    },
    'IAM_ADMIN_USER': {
        'severity': 'CRITICAL',
        'category': 'Privilege Escalation',
        'description': 'IAM user has AdministratorAccess policy',
        'cwe': 'CWE-269',
        'attack_vector': 'Full account takeover'
    },
    'IAM_WILDCARD_POLICY': {
        'severity': 'HIGH',
        'category': 'Privilege Escalation',
        'description': 'IAM policy uses wildcard (*) permissions',
        'cwe': 'CWE-269',
        'attack_vector': 'Lateral movement'
    },
    'IAM_NO_MFA': {
        'severity': 'HIGH',
        'category': 'Authentication',
        'description': 'IAM user has console access without MFA',
        'cwe': 'CWE-308',
        'attack_vector': 'Credential compromise'
    },
    'IAM_OLD_ACCESS_KEY': {
        'severity': 'MEDIUM',
        'category': 'Key Management',
        'description': 'IAM access key is older than 90 days',
        'cwe': 'CWE-324',
        'attack_vector': 'Credential exposure'
    },
    'IAM_WEAK_PASSWORD_POLICY': {
        'severity': 'MEDIUM',
        'category': 'Authentication',
        'description': 'Account password policy is weak',
        'cwe': 'CWE-521',
        'attack_vector': 'Password cracking'
    },
    'IAM_NO_PASSWORD_POLICY': {
        'severity': 'HIGH',
        'category': 'Authentication',
        'description': 'No account password policy configured',
        'cwe': 'CWE-521',
        'attack_vector': 'Weak passwords'
    },
    'SG_OPEN_SSH': {
        'severity': 'HIGH',
        'category': 'Network Exposure',
        'description': 'Security group allows SSH from 0.0.0.0/0',
        'cwe': 'CWE-284',
        'attack_vector': 'Brute-force attack'
    },
    'SG_OPEN_RDP': {
        'severity': 'HIGH',
        'category': 'Network Exposure',
        'description': 'Security group allows RDP from 0.0.0.0/0',
        'cwe': 'CWE-284',
        'attack_vector': 'Brute-force attack'
    },
    'SG_OPEN_DATABASE': {
        'severity': 'CRITICAL',
        'category': 'Network Exposure',
        'description': 'Security group allows database access from 0.0.0.0/0',
        'cwe': 'CWE-284',
        'attack_vector': 'Database compromise'
    },
    'SG_ALL_TRAFFIC': {
        'severity': 'CRITICAL',
        'category': 'Network Exposure',
        'description': 'Security group allows all traffic from 0.0.0.0/0',
        'cwe': 'CWE-284',
        'attack_vector': 'Direct service exploitation'
    },
    'SG_WIDE_PORT_RANGE': {
        'severity': 'HIGH',
        'category': 'Network Exposure',
        'description': 'Security group allows wide port range from 0.0.0.0/0',
        'cwe': 'CWE-284',
        'attack_vector': 'Service enumeration'
    }
}

# Azure Security Rules
AZURE_RULES = {
    'BLOB_PUBLIC_CONTAINER': {
        'severity': 'CRITICAL',
        'category': 'Data Exposure',
        'description': 'Blob container allows public access',
        'cwe': 'CWE-732',
        'attack_vector': 'Direct data exfiltration'
    },
    'NSG_OPEN_SSH': {
        'severity': 'HIGH',
        'category': 'Network Exposure',
        'description': 'NSG allows SSH from Internet',
        'cwe': 'CWE-284',
        'attack_vector': 'Brute-force attack'
    },
    'NSG_OPEN_RDP': {
        'severity': 'HIGH',
        'category': 'Network Exposure',
        'description': 'NSG allows RDP from Internet',
        'cwe': 'CWE-284',
        'attack_vector': 'Brute-force attack'
    },
    'STORAGE_NO_ENCRYPTION': {
        'severity': 'HIGH',
        'category': 'Encryption',
        'description': 'Storage account lacks encryption',
        'cwe': 'CWE-311',
        'attack_vector': 'Data interception'
    }
}

# Attack simulation parameters
ATTACK_SIMULATION = {
    'enabled': True,
    'max_paths': 10,
    'simulate_exploitation': False,  # NEVER set to True
    'logic_only': True
}

# Scanning configuration
SCAN_CONFIG = {
    'timeout': 300,
    'max_retries': 3,
    'parallel_scans': False,
    'read_only': True
}
