# 🎯 QUICK START FOR FRIENDS

## Super Simple Setup (3 Steps!)

### Windows Users:

```bash
# 1. Clone the repo
git clone https://github.com/yourusername/cloud-security-auditor.git
cd cloud-security-auditor

# 2. Run setup (installs everything)
setup.bat

# 3. Start the tool
start.bat
```

### Linux/Mac Users:

```bash
# 1. Clone the repo
git clone https://github.com/yourusername/cloud-security-auditor.git
cd cloud-security-auditor

# 2. Run setup (installs everything)
chmod +x setup.sh
./setup.sh

# 3. Start the tool
source venv/bin/activate
python run.py
```

## That's It! 🎉

The GUI will open. Now you can:
1. Select **AWS** (easiest to start)
2. Click **CONFIGURE CREDENTIALS**
3. Enter your AWS keys
4. Click **START SECURITY SCAN**

## Need AWS Credentials?

1. Go to AWS Console
2. IAM → Users → Your User → Security Credentials
3. Create Access Key
4. Copy the Access Key ID and Secret Access Key

## Troubleshooting

**"Python not found"**
- Install Python 3.8+ from python.org

**"pip not found"**
- Python should include pip. Try: `python -m pip --version`

**"Module not found"**
- Run: `pip install -r requirements.txt`

**Still stuck?**
- Check [SETUP.md](SETUP.md) for detailed instructions
- Open an issue on GitHub

## What Gets Installed?

- `boto3` - AWS SDK (required)
- `jinja2` - Report templates (required)
- Virtual environment (keeps things clean)

## Optional: Azure & GCP

After basic setup works, you can add:

```bash
# Azure support
pip install azure-identity azure-mgmt-storage azure-mgmt-network

# GCP support
pip install google-cloud-storage google-cloud-compute
```

But AWS alone is enough to use the tool!

## File Structure (What You'll See)

```
cloud-security-auditor/
├── run.py              ← Run this to start
├── setup.bat/sh        ← Run this first (one time)
├── start.bat           ← Quick start (Windows)
├── requirements.txt    ← Dependencies list
├── README.md           ← Full documentation
├── SETUP.md            ← Detailed setup guide
└── src/                ← Source code (don't touch)
```

## Pro Tips

✅ Use virtual environment (setup scripts do this automatically)  
✅ Start with AWS (easiest)  
✅ Never commit credentials to git  
✅ Test on a sandbox AWS account first  

## Questions?

1. Check [SETUP.md](SETUP.md)
2. Check [README.md](README.md)
3. Open GitHub issue

Happy scanning! 🔒
