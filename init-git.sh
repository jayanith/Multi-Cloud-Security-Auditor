#!/bin/bash
# Git initialization script for Multi-Cloud Security Auditor

echo "🚀 Initializing Git repository..."

# Initialize git
git init

# Add all files
git add .

# Create initial commit
git commit -m "Initial commit: Multi-Cloud Security Auditor v1.0

Features:
- AWS security scanning (18 checks)
- Azure and GCP support
- Attack simulation engine
- Professional GUI with dark theme
- HTML and JSON reporting
- Real-time scan logs
- Metrics dashboard"

echo "✅ Git repository initialized!"
echo ""
echo "Next steps:"
echo "1. Create a new repository on GitHub"
echo "2. Run: git remote add origin <your-repo-url>"
echo "3. Run: git branch -M main"
echo "4. Run: git push -u origin main"
