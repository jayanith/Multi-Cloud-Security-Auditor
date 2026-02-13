@echo off
REM Git initialization script for Multi-Cloud Security Auditor

echo Initializing Git repository...
echo.

REM Initialize git
git init

REM Add all files
git add .

REM Create initial commit
git commit -m "Initial commit: Multi-Cloud Security Auditor v1.0" -m "Features:" -m "- AWS security scanning (18 checks)" -m "- Azure and GCP support" -m "- Attack simulation engine" -m "- Professional GUI with dark theme" -m "- HTML and JSON reporting" -m "- Real-time scan logs" -m "- Metrics dashboard"

echo.
echo Git repository initialized!
echo.
echo Next steps:
echo 1. Create a new repository on GitHub
echo 2. Run: git remote add origin ^<your-repo-url^>
echo 3. Run: git branch -M main
echo 4. Run: git push -u origin main
echo.
pause
