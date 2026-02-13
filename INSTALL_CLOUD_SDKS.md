# Cloud SDK Installation Guide

## AWS (Already Working)
AWS scanner is fully functional with boto3.

## Azure Setup

### 1. Install Azure SDKs
```bash
pip install azure-identity azure-mgmt-storage azure-mgmt-network
```

### 2. Authenticate with Azure CLI
```bash
# Install Azure CLI first (if not installed)
# Download from: https://aka.ms/installazurecliwindows

# Login to Azure
az login

# Verify login
az account show
```

### 3. Get Your Credentials
- **Subscription ID**: Run `az account show --query id -o tsv`
- **Tenant ID**: Run `az account show --query tenantId -o tsv`

### 4. Use in Tool
1. Select "AZURE" provider
2. Click "CONFIGURE CREDENTIALS"
3. Enter Subscription ID and Tenant ID
4. Click "START SECURITY SCAN"

---

## GCP Setup (Using Service Account)

### 1. Install GCP SDKs
```bash
pip install google-cloud-storage google-cloud-compute
```

### 2. Create Service Account & Download JSON Key
1. Go to: https://console.cloud.google.com/iam-admin/serviceaccounts
2. Select your project
3. Click "CREATE SERVICE ACCOUNT"
4. Give it a name (e.g., "security-scanner")
5. Grant roles: "Viewer" or "Security Reviewer"
6. Click "CREATE KEY" → JSON format
7. Save the JSON file to your computer

### 3. Get Your Project ID
- Find it in the GCP Console dashboard
- Or run: `gcloud config get-value project` (if gcloud installed)

### 4. Use in Tool
1. Select "GCP" provider
2. Click "CONFIGURE CREDENTIALS"
3. Enter Project ID
4. Enter full path to service account JSON file (e.g., `C:\keys\my-project-key.json`)
5. Click "START SECURITY SCAN"

---

## Alternative: GCP with gcloud CLI
If you prefer using gcloud CLI:
```bash
gcloud auth application-default login
```
Then leave the JSON path field empty.

---

## Quick Install All SDKs
```bash
pip install azure-identity azure-mgmt-storage azure-mgmt-network google-cloud-storage google-cloud-compute
```

---

## Notes
- **AWS**: Uses access keys directly (no CLI needed)
- **Azure**: Uses `az login` + Subscription/Tenant IDs
- **GCP**: Uses `gcloud auth` + Project ID
