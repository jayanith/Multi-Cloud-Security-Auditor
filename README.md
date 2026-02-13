# 🔒 Multi-Cloud Security Auditor

A professional desktop application for automated security scanning and penetration testing across AWS, Azure, and GCP cloud environments.

![Python](https://img.shields.io/badge/python-3.8+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)

## 🎯 Features

### 🔍 Comprehensive Security Scanning
- **AWS**: 18 security checks covering S3, IAM, Security Groups, and more
- **Azure**: Storage accounts and Network Security Groups analysis
- **GCP**: Cloud Storage and Firewall rules assessment

### ⚡ Real-Time Monitoring
- Live scan logs with thread-safe UI updates
- Color-coded severity indicators (Critical, High, Medium, Low)
- Interactive metrics dashboard

### 🎯 Attack Simulation
- Logic-based attack chain generation
- MITRE ATT&CK framework mapping
- Theoretical exploitation scenarios (no actual attacks performed)

### 📊 Professional Reporting
- HTML reports with executive summaries
- JSON exports for automation
- Risk scoring and severity breakdown

### 🎨 Modern UI
- Dark-themed professional interface
- Provider-specific color coding (AWS Orange, Azure Blue, GCP Blue)
- Tabbed interface (Scan Logs, Metrics, Reports)

## 📋 Prerequisites

- Python 3.8 or higher
- pip package manager

## 🚀 Quick Start

### 1. Clone Repository
```bash
git clone https://github.com/yourusername/cloud-security-auditor.git
cd cloud-security-auditor
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Run Application
```bash
python tool.py
```

## 🔧 Configuration

### AWS Setup
1. Select **AWS** provider
2. Click **CONFIGURE CREDENTIALS**
3. Enter:
   - Access Key ID
   - Secret Access Key
   - Region (e.g., us-east-1)
4. Click **START SECURITY SCAN**

### Azure Setup (Optional)
```bash
pip install azure-identity azure-mgmt-storage azure-mgmt-network
```
1. Select **AZURE** provider
2. Enter Subscription ID and Tenant ID
3. Authenticate with `az login`

### GCP Setup (Optional)
```bash
pip install google-cloud-storage google-cloud-compute
```
1. Create service account and download JSON key
2. Select **GCP** provider
3. Enter Project ID and path to JSON key file

## 📦 Project Structure

```
cloud-pentest/
├── tool.py                      # Main GUI application
├── core/
│   ├── config.py               # Security rules database
│   └── logger.py               # Logging utilities
├── scanners/
│   ├── aws_scanner.py          # AWS security checks
│   ├── azure_scanner.py        # Azure security checks
│   └── gcp_scanner.py          # GCP security checks
├── attack_simulator/
│   └── attack_chains.py        # Attack scenario generator
├── remediation/
│   └── remediation_generator.py # Fix recommendations
├── reporting/
│   └── report_generator.py     # HTML/JSON report generation
└── requirements.txt            # Python dependencies
```

## 🔒 AWS Security Checks (18 Total)

### S3 Buckets (6 checks)
- ✅ Block Public Access settings
- ✅ Public ACL detection
- ✅ Bucket policy analysis
- ✅ Encryption at rest
- ✅ Versioning status
- ✅ Access logging

### IAM (6 checks)
- ✅ Admin policy detection
- ✅ MFA enforcement
- ✅ Access key age (>90 days)
- ✅ Password policy strength
- ✅ Root account usage
- ✅ Privilege escalation risks

### Security Groups (6 checks)
- ✅ SSH exposure (port 22)
- ✅ RDP exposure (port 3389)
- ✅ Database port exposure
- ✅ Wide IP ranges (0.0.0.0/0)
- ✅ Unrestricted egress
- ✅ Unused security groups

## 📊 Sample Output

### Metrics Dashboard
```
CRITICAL: 3  |  HIGH: 7  |  MEDIUM: 5  |  LOW: 2
Risk Score: 68/100 (HIGH)
```

### Attack Scenarios
```
🎯 S3 Data Exfiltration Chain
   Severity: CRITICAL
   Steps:
   1. Enumerate public S3 buckets
   2. Download sensitive data
   3. Exfiltrate to external storage
   MITRE ATT&CK: T1530, T1567
```

## 🛡️ Security & Disclaimer

⚠️ **IMPORTANT**: This tool is for **authorized security testing only**. 

- All attack scenarios are **logic-based simulations**
- No actual exploitation or penetration testing is performed
- Credentials are stored in memory only (never saved to disk)
- Use only on cloud accounts you own or have explicit permission to test

## 📝 License

MIT License - see [LICENSE](LICENSE) file for details

## 🤝 Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Submit a pull request

## 📧 Contact

For questions or support, please open an issue on GitHub.

## 🙏 Acknowledgments

- AWS Security Best Practices
- MITRE ATT&CK Framework
- OWASP Cloud Security Guidelines

---

**⭐ Star this repo if you find it useful!**
