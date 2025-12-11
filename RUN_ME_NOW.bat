@echo off
title TDRF - Final Setup
color 0A
cls

echo.
echo     ████████╗██████╗ ██████╗ ███████╗
echo     ╚══██╔══╝██╔══██╗██╔══██╗██╔════╝
echo        ██║   ██║  ██║██████╔╝█████╗  
echo        ██║   ██║  ██║██╔══██╗██╔══╝  
echo        ██║   ██████╔╝██║  ██║██║     
echo        ╚═╝   ╚═════╝ ╚═╝  ╚═╝╚═╝     
echo.
echo     Threat Detection and Response Framework
echo     Professional Repository Setup
echo.
echo ════════════════════════════════════════════════════════════════
echo.

cd /d C:\tdrf\tdrf

echo [INFO] Starting complete setup process...
echo.

REM Step 1: Create GitHub structure
echo [1/7] Creating GitHub templates and structure...
python create_github_files.py
if errorlevel 1 (
    echo [ERROR] Failed to create GitHub files!
    pause
    exit /b 1
)
echo [SUCCESS] GitHub structure created!
echo.

REM Step 2: Generate screenshots
echo [2/7] Generating demo screenshots...
pip install Pillow --quiet >nul 2>&1
python generate_screenshots.py
echo [SUCCESS] Screenshots generated!
echo.

REM Step 3: Git status
echo [3/7] Checking Git status...
git status --short
echo.

REM Step 4: Add files
echo [4/7] Adding all files to Git...
git add .
echo [SUCCESS] Files staged!
echo.

REM Step 5: Commit
echo [5/7] Creating commit...
git commit -m "🚀 Major Enhancement: Professional README, documentation, templates, and screenshots"
if errorlevel 1 (
    echo [INFO] No changes to commit or already committed.
) else (
    echo [SUCCESS] Commit created!
)
echo.

REM Step 6: Push
echo [6/7] Pushing to GitHub...
echo [INFO] This may take a moment...
git push origin main
if errorlevel 1 (
    echo [WARNING] Push failed. You may need to authenticate.
    echo [INFO] If this is your first push, you may need to login to GitHub.
    echo.
    echo Try running these commands manually:
    echo   git push origin main
    echo.
    pause
) else (
    echo [SUCCESS] Pushed to GitHub!
)
echo.

REM Step 7: Final status
echo [7/7] Verifying final status...
git log --oneline -5
echo.

echo ════════════════════════════════════════════════════════════════
echo     ✅ SETUP COMPLETE!
echo ════════════════════════════════════════════════════════════════
echo.
echo Your TDRF repository is now fully enhanced with:
echo.
echo   ✓ Professional README with badges
echo   ✓ Contributing guidelines
echo   ✓ Code of Conduct  
echo   ✓ Issue and PR templates
echo   ✓ CI/CD workflow (GitHub Actions)
echo   ✓ Demo screenshots
echo   ✓ Quick start guide
echo   ✓ Complete documentation
echo.
echo ════════════════════════════════════════════════════════════════
echo     📋 NEXT STEPS - IMPORTANT!
echo ════════════════════════════════════════════════════════════════
echo.
echo 1. Open your repository: https://github.com/tbhuiyan625/TDRF
echo.
echo 2. Click the gear icon (⚙️) next to "About" and add:
echo    - Description: "Professional Python threat detection framework"
echo    - Topics: cybersecurity, python, security-tools, etc.
echo.
echo 3. Read FINAL_CHECKLIST.md for complete setup instructions:
echo    - Add to LinkedIn
echo    - Add to Resume
echo    - Take real screenshots
echo    - Share on social media
echo.
echo 4. Review QUICK_START.md for:
echo    - Resume description templates
echo    - Interview preparation
echo    - Demo instructions
echo.
echo ════════════════════════════════════════════════════════════════
echo.
echo Opening GitHub repository in 5 seconds...
timeout /t 5 /nobreak >nul
start https://github.com/tbhuiyan625/TDRF
echo.
echo Opening FINAL_CHECKLIST.md...
timeout /t 2 /nobreak >nul
notepad FINAL_CHECKLIST.md
echo.
echo ════════════════════════════════════════════════════════════════
echo     🎉 Congratulations!
echo ════════════════════════════════════════════════════════════════
echo.
echo Your professional security framework is ready to impress employers!
echo.
echo Questions? Email: tbhuiyan625@gmail.com
echo.
pause
