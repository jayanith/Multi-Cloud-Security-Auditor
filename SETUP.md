# 🚀 Setup Guide

Complete installation and setup instructions for Multi-Cloud Security Auditor.

## 📋 Prerequisites

- **Python**: 3.8 or higher
- **pip**: Latest version
- **Git**: For cloning the repository

## 🔧 Installation Steps

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/cloud-security-auditor.git
cd cloud-security-auditor
```

### 2. Create Virtual Environment (Recommended)

**Windows:**
```bash
python -m venv venv
venv\Scripts\activate
```

**Linux/macOS:**
```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Dependencies

**Core dependencies (AWS support):**
```bash
pip install -r requirements.txt
```

**Optional - Azure support:**
```bash
pip install azure-identity azure-mgmt-storage azure-mgmt-network
```

**Optional - GCP support:**
```bash
pip install google-cloud-storage google-cloud-compute
```

**Install all at once:**
```bash
pip install boto3 jinja2 azure-identity azure-mgmt-storage azure-mgmt-network google-cloud-storage google-cloud-compute
```

### 4. Verify Installation

```bash
python run.py
```

The GUI should launch successfully.

## ☁️ Cloud Provider Setup

### AWS Configuration

1. **Get AWS Credentials:**
   - Go to AWS Console → IAM → Users → Security Credentials
   - Create Access Key
   - Save Access Key ID and Secret Access Key

2. **In the Tool:**
   - Select **AWS** provider
   - Click **CONFIGURE CREDENTIALS**
   - Enter Access Key ID, Secret Access Key, and Region
   - Click **START SECURITY SCAN**

### Azure Configuration (Optional)

1. **Install Azure CLI:**
   - Download from: https://aka.ms/installazurecliwindows

2. **Authenticate:**
   ```bash
   az login
   ```

3. **Get Credentials:**
   ```bash
   # Get Subscription ID
   az account show --query id -o tsv
   
   # Get Tenant ID
   az account show --query tenantId -o tsv
   ```

4. **In the Tool:**
   - Select **AZURE** provider
   - Enter Subscription ID and Tenant ID

### GCP Configuration (Optional)

1. **Create Service Account:**
   - Go to: https://console.cloud.google.com/iam-admin/serviceaccounts
   - Create service account with "Viewer" role
   - Create JSON key and download

2. **In the Tool:**
   - Select **GCP** provider
   - Enter Project ID
   - Enter path to JSON key file

## 🎯 Quick Start

1. **Launch the tool:**
   ```bash
   python run.py
   ```

2. **Configure credentials** for your cloud provider

3. **Click "START SECURITY SCAN"**

4. **View results** in the Metrics tab

5. **Download reports** from the Reports tab

## 🐛 Troubleshooting

### "Module not found" error
```bash
pip install -r requirements.txt
```

### "AWS credentials not found"
- Verify Access Key ID and Secret Access Key
- Check region format (e.g., us-east-1)

### "Azure SDK not installed"
```bash
pip install azure-identity azure-mgmt-storage azure-mgmt-network
```

### "GCP credentials not found"
- Verify JSON key file path is correct
- Ensure service account has proper permissions

## 📚 Additional Resources

- [Architecture Documentation](docs/ARCHITECTURE.md)
- [Cloud SDK Installation](docs/INSTALL_CLOUD_SDKS.md)
- [GitHub Issues](https://github.com/yourusername/cloud-security-auditor/issues)

## 💡 Tips

- Use virtual environment to avoid dependency conflicts
- Start with AWS (easiest to set up)
- Keep credentials secure (never commit to git)
- Run scans on test accounts first

## 🆘 Need Help?

Open an issue on GitHub with:
- Error message
- Python version
- Operating system
- Steps to reproduce
