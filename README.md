# 🔒 Multi-Cloud Security Auditor

A professional desktop application for automated security scanning and penetration testing across AWS, Azure, and GCP cloud environments.

![Python](https://img.shields.io/badge/python-3.8+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)

## 🎯 Features

### 🔍 Comprehensive Security Scanning
- **AWS**: 18 security checks covering S3, IAM, Security Groups
- **Azure**: Storage accounts and Network Security Groups
- **GCP**: Cloud Storage and Firewall rules

### ⚡ Real-Time Monitoring
- Live scan logs with color-coded severity
- Interactive metrics dashboard
- Attack scenario visualization

### 📊 Professional Reporting
- HTML reports with executive summaries
- JSON exports for automation
- Risk scoring and MITRE ATT&CK mapping

### 🎨 Modern UI
- Dark-themed professional interface
- Provider-specific color coding
- Tabbed interface (Scan Logs, Metrics, Reports)

## 🚀 Quick Start

### For Your Friends (First Time Setup)

```bash
# 1. Clone the repository
git clone https://github.com/yourusername/cloud-security-auditor.git
cd cloud-security-auditor

# 2. Create virtual environment
python -m venv venv

# Windows:
venv\Scripts\activate

# Linux/macOS:
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run the tool
python run.py
```

**That's it!** The GUI will launch and you can start scanning.

## 📋 Prerequisites

- Python 3.8 or higher
- pip package manager
- Git (for cloning)

## 📦 Project Structure

```
cloud-security-auditor/
├── run.py                      # Main entry point ⭐
├── requirements.txt            # Python dependencies
├── SETUP.md                    # Detailed setup guide
├── LICENSE                     # MIT License
├── .gitignore                  # Git exclusions
│
├── src/                        # Source code
│   ├── tool.py                # Main GUI application
│   ├── core/                  # Core utilities
│   │   ├── config.py         # Security rules
│   │   └── logger.py         # Logging
│   ├── scanners/              # Cloud scanners
│   │   ├── aws_scanner.py    # AWS checks
│   │   ├── azure_scanner.py  # Azure checks
│   │   └── gcp_scanner.py    # GCP checks
│   ├── attack_simulator/      # Attack chains
│   ├── remediation/           # Fix recommendations
│   └── reporting/             # Report generation
│
├── docs/                       # Documentation
│   ├── ARCHITECTURE.md        # Technical details
│   └── INSTALL_CLOUD_SDKS.md  # Cloud setup
│
└── examples/                   # Example configs
```

## 🔧 Configuration

### AWS (Recommended - Easiest)

1. Get AWS credentials from IAM Console
2. In the tool:
   - Select **AWS**
   - Click **CONFIGURE CREDENTIALS**
   - Enter Access Key, Secret Key, Region
   - Click **START SECURITY SCAN**

### Azure (Optional)

```bash
pip install azure-identity azure-mgmt-storage azure-mgmt-network
az login
```

### GCP (Optional)

```bash
pip install google-cloud-storage google-cloud-compute
```
Provide service account JSON key file.

**See [SETUP.md](SETUP.md) for detailed instructions.**

## 🔒 AWS Security Checks (18 Total)

### S3 Buckets (6)
✅ Block Public Access | ✅ Public ACL | ✅ Bucket Policy  
✅ Encryption | ✅ Versioning | ✅ Access Logging

### IAM (6)
✅ Admin Policies | ✅ MFA | ✅ Old Access Keys  
✅ Password Policy | ✅ Root Account | ✅ Privilege Escalation

### Security Groups (6)
✅ SSH Exposure | ✅ RDP Exposure | ✅ Database Ports  
✅ Wide IP Ranges | ✅ Unrestricted Egress | ✅ Unused Groups

## 📊 Sample Output

```
🔍 Scan Results:
CRITICAL: 3  |  HIGH: 7  |  MEDIUM: 5  |  LOW: 2
Risk Score: 68/100 (HIGH)

🎯 Attack Scenarios:
1. S3 Data Exfiltration Chain (CRITICAL)
2. IAM Privilege Escalation (HIGH)
3. Security Group Lateral Movement (MEDIUM)
```

## 🛡️ Security & Disclaimer

⚠️ **IMPORTANT**: 
- For **authorized testing only**
- All attacks are **simulated** (no actual exploitation)
- Credentials stored in memory only
- Use on accounts you own or have permission to test

## 📝 License

MIT License - see [LICENSE](LICENSE)

## 🤝 Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing`)
5. Open Pull Request

## 📧 Support

Open an issue on GitHub for:
- Bug reports
- Feature requests
- Questions

## 🙏 Acknowledgments

- AWS Security Best Practices
- MITRE ATT&CK Framework
- OWASP Cloud Security

---

**⭐ Star this repo if you find it useful!**

Made with ❤️ for cloud security
