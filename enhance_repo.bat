@echo off
echo ========================================
echo  TDRF Repository Enhancement Script
echo ========================================
echo.

cd /d C:\tdrf\tdrf

echo [1/5] Creating GitHub template directories...
python create_github_files.py

echo.
echo [2/5] Adding all new files to git...
git add .

echo.
echo [3/5] Creating commit...
git commit -m "Enhance repository: Add professional README, templates, and documentation"

echo.
echo [4/5] Pushing to GitHub...
git push origin main

echo.
echo [5/5] Opening GitHub repository...
start https://github.com/tbhuiyan625/TDRF

echo.
echo ========================================
echo  ENHANCEMENT COMPLETE!
echo ========================================
echo.
echo Your repository now has:
echo  ✓ Professional README with badges
echo  ✓ Contributing guidelines
echo  ✓ Code of Conduct
echo  ✓ Issue templates
echo  ✓ PR templates
echo  ✓ CI/CD workflow
echo.
echo Next steps:
echo 1. Add screenshots to screenshots/ folder
echo 2. Update repository description on GitHub
echo 3. Add topics/tags to your repo
echo.
pause
