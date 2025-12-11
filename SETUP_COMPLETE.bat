@echo off
color 0A
echo.
echo ════════════════════════════════════════════════════════════════
echo  TDRF - Complete Repository Enhancement
echo ════════════════════════════════════════════════════════════════
echo.
echo This script will:
echo  [1] Create GitHub templates and documentation
echo  [2] Generate demo screenshots
echo  [3] Commit all changes
echo  [4] Push to GitHub
echo  [5] Update repository settings
echo.
pause

cd /d C:\tdrf\tdrf

echo.
echo ════════════════════════════════════════════════════════════════
echo  Step 1: Creating GitHub Files
echo ════════════════════════════════════════════════════════════════
python create_github_files.py

echo.
echo ════════════════════════════════════════════════════════════════
echo  Step 2: Generating Screenshots
echo ════════════════════════════════════════════════════════════════
pip install Pillow --quiet
python generate_screenshots.py

echo.
echo ════════════════════════════════════════════════════════════════
echo  Step 3: Checking Git Status
echo ════════════════════════════════════════════════════════════════
git status

echo.
echo ════════════════════════════════════════════════════════════════
echo  Step 4: Adding Files to Git
echo ════════════════════════════════════════════════════════════════
git add .

echo.
echo ════════════════════════════════════════════════════════════════
echo  Step 5: Creating Commit
echo ════════════════════════════════════════════════════════════════
git commit -m "🚀 Major update: Professional README, GitHub templates, documentation, and screenshots"

echo.
echo ════════════════════════════════════════════════════════════════
echo  Step 6: Pushing to GitHub
echo ════════════════════════════════════════════════════════════════
git push origin main

echo.
echo ════════════════════════════════════════════════════════════════
echo  ✅ REPOSITORY ENHANCEMENT COMPLETE!
echo ════════════════════════════════════════════════════════════════
echo.
echo Your repository now includes:
echo.
echo  ✓ Professional README with badges and sections
echo  ✓ Contributing guidelines (CONTRIBUTING.md)
echo  ✓ Code of Conduct (CODE_OF_CONDUCT.md)
echo  ✓ Bug report template
echo  ✓ Feature request template
echo  ✓ Pull request template
echo  ✓ CI/CD workflow (GitHub Actions)
echo  ✓ Demo screenshots
echo.
echo ════════════════════════════════════════════════════════════════
echo  NEXT STEPS - IMPORTANT!
echo ════════════════════════════════════════════════════════════════
echo.
echo 1. Update Repository Description:
echo    Go to: https://github.com/tbhuiyan625/TDRF
echo    Click the gear icon (⚙️) next to "About"
echo    Add description:
echo    "Professional Python threat detection framework with log 
echo     analysis, port scanning, and automated security reporting"
echo.
echo 2. Add Repository Topics:
echo    Add these topics/tags:
echo     - cybersecurity
echo     - python
echo     - security-tools
echo     - threat-detection
echo     - penetration-testing
echo     - network-security
echo     - port-scanner
echo     - log-analysis
echo     - incident-response
echo     - security-automation
echo.
echo 3. Enable GitHub Pages (optional):
echo    Settings → Pages → Deploy from main branch
echo.
echo 4. Add Social Preview Image:
echo    Settings → Social preview → Upload image
echo    Use: screenshots/banner.png
echo.
echo 5. Take Real Screenshots:
echo    - Run: python -m tdrf --cli (screenshot the menu)
echo    - Run: python -m tdrf --gui (screenshot the GUI)
echo    - Generate a report and screenshot it
echo    - Replace placeholder images in screenshots/ folder
echo.
echo 6. Update Your LinkedIn/Resume:
echo    Project Link: https://github.com/tbhuiyan625/TDRF
echo    Use this description:
echo    "Developed TDRF, a comprehensive Python-based security
echo     framework featuring real-time threat detection, multi-
echo     threaded port scanning, event correlation, and automated
echo     reporting. Demonstrates expertise in cybersecurity,
echo     network programming, and Python development."
echo.
echo ════════════════════════════════════════════════════════════════
echo.
echo Opening your repository in browser...
timeout /t 3 /nobreak >nul
start https://github.com/tbhuiyan625/TDRF
echo.
echo Press any key to exit...
pause >nul
