# How to Push Raven to GitHub

## Option 1: Using gh CLI (Recommended)

gh CLI is already installed. Run these commands in your terminal:

```bash
cd /run/media/wulf/DANE/Projekty/raven

# 1. Login to GitHub (opens browser)
gh auth login
# Choose: GitHub.com -> HTTPS -> Login with a web browser
# Follow the browser instructions

# 2. Create the repo and push
gh repo create raven --public --source=. --push
```

Done! Your repo will be at: `https://github.com/YOUR_USERNAME/raven`

## Option 2: Manual (Web + Git)

1. Go to https://github.com/new
2. Repository name: `raven`
3. Make it **Public**
4. **DO NOT** initialize with README (we already have one)
5. Click "Create repository"
6. Run these commands:

```bash
cd /run/media/wulf/DANE/Projekty/raven
git remote add origin https://github.com/YOUR_USERNAME/raven.git
git branch -M main
git push -u origin main
```

Done!

## After pushing

- Add topics: `security`, `static-analysis`, `vibe-coding`, `ai`, `bug-bounty`
- Pin the repo on your profile
- Share it! 🚀
