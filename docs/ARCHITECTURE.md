# Project Architecture & Design Document

## Executive Summary

**Project Name:** Multi-Cloud Automated Pentesting & Security Auditor  
**Version:** 1.0.0  
**Purpose:** Educational cloud security assessment tool  
**Supported Clouds:** AWS (full), Azure (partial), GCP (placeholder)  
**License:** MIT with ethical use disclaimer  

## Design Philosophy

### Core Principles

1. **Safety First**: Read-only operations, no destructive actions
2. **Educational Value**: Teach cloud security through practical examples
3. **Realistic Simulation**: Logic-based attack chains without actual exploitation
4. **Actionable Output**: Provide remediation guidance, not just findings
5. **Free Tier Compatible**: Minimize costs for students

### What is REAL vs SIMULATED

| Component | Real | Simulated | Explanation |
|-----------|------|-----------|-------------|
| Cloud API Calls | ✅ | ❌ | Uses boto3/azure-mgmt to query resources |
| Configuration Analysis | ✅ | ❌ | Checks actual ACLs, policies, rules |
| Vulnerability Detection | ✅ | ❌ | Identifies real misconfigurations |
| Attack Chains | ❌ | ✅ | Theoretical paths, not executed |
| Exploitation | ❌ | ✅ | Explains what COULD happen |
| Data Access | ❌ | ✅ | Never reads actual data |
| Report Generation | ✅ | ❌ | Creates real JSON/HTML reports |

## System Architecture

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        CLI Interface                         │
│                         (main.py)                            │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ├─── Core Components
                     │    ├── config.py (Rules & Settings)
                     │    └── logger.py (Audit Trail)
                     │
                     ├─── Scanners (Cloud-Specific)
                     │    ├── aws_scanner.py
                     │    ├── azure_scanner.py
                     │    └── gcp_scanner.py (stub)
                     │
                     ├─── Attack Simulator
                     │    └── attack_chains.py
                     │
                     ├─── Remediation Generator
                     │    └── remediation_generator.py
                     │
                     └─── Report Generator
                          └── report_generator.py
```

### Component Details

#### 1. Core Components

**config.py**
- Security rules database (AWS_RULES, AZURE_RULES)
- Severity levels (CRITICAL, HIGH, MEDIUM, LOW)
- CWE mappings
- Attack vector descriptions

**logger.py**
- Structured logging with colors
- Audit trail for compliance
- Progress tracking
- Finding categorization

#### 2. Cloud Scanners

**aws_scanner.py**
- S3 bucket scanning (ACL, policy, encryption)
- IAM policy analysis (admin users, wildcards)
- Security Group analysis (open ports)
- Uses boto3 SDK
- Requires SecurityAudit policy

**azure_scanner.py**
- Storage account scanning (public containers, encryption)
- NSG analysis (open ports)
- Uses azure-mgmt SDK
- Requires Reader role

**gcp_scanner.py**
- Placeholder for future implementation
- Architecture defined, not implemented

#### 3. Attack Simulator

**attack_chains.py**
- Generates logic-based attack scenarios
- Maps to MITRE ATT&CK framework
- Calculates risk scores
- Includes real-world breach examples
- Clear "SIMULATION ONLY" disclaimers

Attack Types:
- Data Exfiltration (public storage)
- Privilege Escalation (IAM misconfigurations)
- Network Intrusion (open ports)
- Lateral Movement (multi-stage)

#### 4. Remediation Generator

**remediation_generator.py**
- Step-by-step fix instructions
- AWS CLI commands (copy-paste ready)
- Azure CLI commands
- Terraform configuration examples
- IAM policy examples
- Prevention strategies
- Official documentation links

#### 5. Report Generator

**report_generator.py**
- JSON output (machine-readable)
- HTML output (human-readable)
- Executive summary with risk score
- Detailed findings
- Attack chain visualizations
- Remediation guidance
- Legal disclaimers

## Data Flow

```
1. User Input
   └─> Provider selection (AWS/Azure/GCP)
   └─> Configuration options

2. Authentication
   └─> Verify cloud credentials
   └─> Check permissions

3. Scanning Phase
   └─> Query cloud APIs (read-only)
   └─> Collect resource configurations
   └─> Analyze against security rules
   └─> Generate findings

4. Analysis Phase
   └─> Group findings by severity
   └─> Simulate attack chains (logic-based)
   └─> Calculate risk score
   └─> Generate remediation templates

5. Reporting Phase
   └─> Create JSON report
   └─> Generate HTML report
   └─> Save to disk

6. Output
   └─> Console summary
   └─> Report file paths
   └─> Exit code (0=clean, 1=findings, 2=critical)
```

## Security Rules Engine

### Rule Structure

```python
{
    'RULE_ID': {
        'severity': 'CRITICAL|HIGH|MEDIUM|LOW',
        'category': 'Data Exposure|Privilege Escalation|Network Exposure|Encryption',
        'description': 'Human-readable description',
        'cwe': 'CWE-XXX',
        'attack_vector': 'How this could be exploited'
    }
}
```

### AWS Rules (7 rules)

1. **S3_PUBLIC_BUCKET** (CRITICAL)
   - Detects: Public read/write via ACL or policy
   - Risk: Data exfiltration
   - CWE-732: Incorrect Permission Assignment

2. **S3_NO_ENCRYPTION** (HIGH)
   - Detects: Missing server-side encryption
   - Risk: Data interception
   - CWE-311: Missing Encryption

3. **IAM_ADMIN_USER** (CRITICAL)
   - Detects: AdministratorAccess policy
   - Risk: Full account takeover
   - CWE-269: Improper Privilege Management

4. **IAM_WILDCARD_POLICY** (HIGH)
   - Detects: Wildcard (*) permissions
   - Risk: Lateral movement
   - CWE-269: Improper Privilege Management

5. **SG_OPEN_SSH** (HIGH)
   - Detects: SSH (22) from 0.0.0.0/0
   - Risk: Brute-force attack
   - CWE-284: Improper Access Control

6. **SG_OPEN_RDP** (HIGH)
   - Detects: RDP (3389) from 0.0.0.0/0
   - Risk: Brute-force attack
   - CWE-284: Improper Access Control

7. **SG_ALL_TRAFFIC** (CRITICAL)
   - Detects: All ports from 0.0.0.0/0
   - Risk: Direct exploitation
   - CWE-284: Improper Access Control

### Azure Rules (4 rules)

1. **BLOB_PUBLIC_CONTAINER** (CRITICAL)
2. **NSG_OPEN_SSH** (HIGH)
3. **NSG_OPEN_RDP** (HIGH)
4. **STORAGE_NO_ENCRYPTION** (HIGH)

## Attack Simulation Logic

### Simulation Algorithm

```python
def simulate_attack(finding):
    1. Identify entry point (misconfiguration)
    2. Map to MITRE ATT&CK technique
    3. Generate step-by-step progression
    4. Assess impact (CIA triad)
    5. Calculate likelihood
    6. Reference real-world example
    7. Add "SIMULATION ONLY" disclaimer
```

### Attack Chain Structure

```python
{
    'chain_id': 'CHAIN-001',
    'name': 'Attack Name',
    'severity': 'CRITICAL',
    'steps': [
        {
            'step': 1,
            'action': 'Reconnaissance',
            'description': 'What happens',
            'technique': 'MITRE ATT&CK T1234',
            'simulated': True  # Always True
        }
    ],
    'impact': {
        'confidentiality': 'HIGH',
        'integrity': 'LOW',
        'availability': 'NONE',
        'business_impact': 'Description'
    },
    'likelihood': 'HIGH|MEDIUM|LOW',
    'exploitability': 'Description',
    'real_world_example': 'Breach reference',
    'disclaimer': 'SIMULATION ONLY - ...'
}
```

### Risk Score Calculation

```python
risk_score = Σ(severity_score × likelihood_score) / max_possible × 100

severity_scores = {
    'CRITICAL': 10,
    'HIGH': 7,
    'MEDIUM': 4,
    'LOW': 2
}

likelihood_scores = {
    'HIGH': 3,
    'MEDIUM': 2,
    'LOW': 1
}
```

## Remediation Templates

### Template Structure

```python
{
    'finding_id': 'RULE_ID',
    'resource': 'Resource identifier',
    'priority': 'CRITICAL|HIGH|MEDIUM|LOW',
    'remediation_steps': ['Step 1', 'Step 2', ...],
    'aws_cli': 'CLI commands',
    'azure_cli': 'CLI commands',
    'terraform': 'Terraform config',
    'policy_example': 'IAM policy JSON',
    'prevention': 'How to prevent',
    'references': ['URL1', 'URL2']
}
```

## Error Handling

### Credential Errors
- Catch NoCredentialsError (AWS)
- Catch AzureError (Azure)
- Provide clear setup instructions

### Permission Errors
- Catch AccessDenied exceptions
- Suggest required IAM policies/roles
- Continue scanning other resources

### API Rate Limits
- Implement retry logic (max 3 attempts)
- Add exponential backoff
- Log rate limit warnings

### Resource Not Found
- Handle gracefully
- Log warning, continue scan
- Don't fail entire scan

## Testing Strategy

### Unit Tests (Future)
- Test each scanner independently
- Mock cloud API responses
- Verify rule detection logic

### Integration Tests
- Test with real cloud accounts
- Use intentionally vulnerable resources
- Verify end-to-end flow

### Demo Environment
- `create_demo_env.py` - Creates test resources
- `cleanup_demo.py` - Removes test resources
- Free tier compatible

## Performance Considerations

### Optimization
- Sequential scanning (no parallel by default)
- Minimal API calls
- Efficient data structures
- Lazy loading where possible

### Scalability
- Handles 100s of resources
- May hit rate limits on 1000s
- Consider pagination for large environments

### Resource Usage
- Low memory footprint
- No persistent storage
- Reports saved to disk only

## Compliance & Ethics

### Legal Compliance
- Read-only operations
- No data exfiltration
- Requires authorization
- Clear disclaimers

### Ethical Guidelines
- Educational purpose only
- No actual exploitation
- Responsible disclosure
- Respect privacy

### Academic Integrity
- Original code
- Proper attribution
- No plagiarism
- Honest capabilities

## Future Enhancements

### Phase 2
- [ ] GCP full implementation
- [ ] Kubernetes security scanning
- [ ] Container image scanning

### Phase 3
- [ ] Compliance frameworks (CIS, NIST)
- [ ] Custom rule engine
- [ ] Web dashboard (Flask/Streamlit)

### Phase 4
- [ ] CI/CD integration
- [ ] SIEM integration
- [ ] Automated remediation
- [ ] Historical trending

## Limitations

### Technical Limitations
1. Configuration-focused (not vulnerability scanning)
2. No application code analysis
3. No runtime behavior analysis
4. Limited to common misconfigurations

### Scope Limitations
1. Not exhaustive (covers ~15 rules)
2. No zero-day detection
3. No compliance certification
4. Educational, not production-grade

### Operational Limitations
1. Requires cloud credentials
2. Subject to API rate limits
3. No real-time monitoring
4. Point-in-time assessment

## Conclusion

This project demonstrates:
- ✅ Cloud security knowledge
- ✅ Software engineering skills
- ✅ Ethical security practices
- ✅ Practical problem-solving

It provides:
- ✅ Real value (detects actual issues)
- ✅ Educational content (teaches concepts)
- ✅ Safe operation (no exploitation)
- ✅ Professional output (quality reports)

**Suitable for academic evaluation and portfolio demonstration.**

---

**Document Version:** 1.0  
**Last Updated:** 2024  
**Status:** Complete and Ready for Evaluation
