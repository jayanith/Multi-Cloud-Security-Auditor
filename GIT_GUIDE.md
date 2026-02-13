# Git Commands for This Project

## Initial Setup (First Time)

```bash
# Initialize git repository
git init

# Add all files
git add .

# Create first commit
git commit -m "Initial commit: Multi-Cloud Security Auditor v1.0"

# Create GitHub repo, then link it
git remote add origin https://github.com/yourusername/cloud-security-auditor.git

# Push to GitHub
git branch -M main
git push -u origin main
```

## For Your Friends (Cloning)

```bash
# Clone the repository
git clone https://github.com/yourusername/cloud-security-auditor.git
cd cloud-security-auditor

# Run setup
setup.bat  # Windows
./setup.sh # Linux/Mac

# Start using
python run.py
```

## Making Changes

```bash
# Check status
git status

# Add changes
git add .

# Commit with message
git commit -m "Add new feature"

# Push to GitHub
git push
```

## Updating Your Local Copy

```bash
# Pull latest changes
git pull origin main

# Reinstall dependencies if requirements.txt changed
pip install -r requirements.txt
```

## Creating a Feature Branch

```bash
# Create and switch to new branch
git checkout -b feature/my-new-feature

# Make changes, then commit
git add .
git commit -m "Add my new feature"

# Push branch to GitHub
git push origin feature/my-new-feature

# Create Pull Request on GitHub
```

## Useful Commands

```bash
# View commit history
git log --oneline

# See what changed
git diff

# Undo uncommitted changes
git checkout -- filename

# View remote URL
git remote -v

# Update remote URL
git remote set-url origin https://github.com/newusername/repo.git
```

## .gitignore Protects You

These files are automatically ignored (won't be committed):
- `*.log` - Log files
- `*.json` - Credential files
- `__pycache__/` - Python cache
- `venv/` - Virtual environment
- `reports/` - Generated reports

So you can't accidentally commit secrets! 🔒

## First Time Git Push

```bash
# 1. Create repo on GitHub (don't initialize with README)

# 2. In your local folder:
git init
git add .
git commit -m "Initial commit"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/cloud-security-auditor.git
git push -u origin main
```

## Common Issues

**"Permission denied (publickey)"**
- Set up SSH keys: https://docs.github.com/en/authentication/connecting-to-github-with-ssh

**"Repository not found"**
- Check the URL: `git remote -v`
- Make sure repo exists on GitHub

**"Merge conflict"**
- Pull first: `git pull origin main`
- Resolve conflicts manually
- Commit and push

## Pro Tips

✅ Commit often with clear messages  
✅ Pull before you push  
✅ Use branches for new features  
✅ Never commit credentials (gitignore handles this)  
✅ Write meaningful commit messages  

## Example Workflow

```bash
# Start working
git pull origin main

# Make changes to files
# ...

# Check what changed
git status
git diff

# Stage and commit
git add .
git commit -m "Fix: Improved error handling in AWS scanner"

# Push to GitHub
git push origin main
```

Done! 🎉
