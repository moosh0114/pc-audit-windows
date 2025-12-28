@echo off
chcp 65001 > nul
title PC Audit - One Click Runner

echo ============================================
echo   PC AUDIT - One Click System Scanner
echo ============================================
echo.

REM 切換到 bat 所在資料夾（避免路徑問題）
cd /d "%~dp0"

REM 嘗試用 python 啟動
echo [INFO] Running pc_audit.py ...
python pc_audit.py

IF ERRORLEVEL 1 (
    echo.
    echo [ERROR] Python execution failed.
    echo Make sure Python is installed and added to PATH.
)

echo.
echo ============================================
echo   DONE. Check Desktop for output files.
echo ============================================
echo.
pause
