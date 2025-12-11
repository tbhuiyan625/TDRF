@echo off
echo ========================================
echo  TDRF GitHub Setup Script
echo ========================================
echo.

cd /d C:\tdrf\tdrf

echo [1/7] Initializing Git repository...
git init

echo.
echo [2/7] Configuring Git user...
git config user.name "tbhuiyan625"
git config user.email "tbhuiyan625@users.noreply.github.com"

echo.
echo [3/7] Adding all files...
git add .

echo.
echo [4/7] Creating initial commit...
git commit -m "Initial commit: Complete TDRF security framework - Professional threat detection and response tool with log analysis, port scanning, event correlation, and reporting capabilities"

echo.
echo [5/7] Adding remote repository...
git remote add origin https://github.com/tbhuiyan625/TDRF.git

echo.
echo [6/7] Setting main branch...
git branch -M main

echo.
echo ========================================
echo  READY TO PUSH TO GITHUB!
echo ========================================
echo.
echo IMPORTANT: Before pushing, you need to:
echo 1. Go to https://github.com/new
echo 2. Create a new repository named: TDRF
echo 3. Make it PUBLIC
echo 4. DO NOT initialize with README
echo 5. Click "Create repository"
echo.
echo After creating the repo, press any key to push...
pause

echo.
echo [7/7] Pushing to GitHub...
git push -u origin main

echo.
echo ========================================
echo  SUCCESS!
echo ========================================
echo.
echo Your TDRF project is now on GitHub:
echo https://github.com/tbhuiyan625/TDRF
echo.
pause
