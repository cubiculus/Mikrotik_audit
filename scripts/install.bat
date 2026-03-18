@echo off
REM Quick installation script for MikroTik Audit Tool (Windows)
REM Run this script to set up the project in one command

echo ========================================
echo MikroTik Audit Tool - Quick Install
echo ========================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python is not installed or not in PATH
    echo Please install Python 3.9+ from https://www.python.org/downloads/
    pause
    exit /b 1
)

echo [1/4] Python found
echo.

REM Create virtual environment if it doesn't exist
if not exist "venv" (
    echo [2/4] Creating virtual environment...
    python -m venv venv
) else (
    echo [2/4] Virtual environment already exists
)
echo.

REM Activate virtual environment and install dependencies
echo [3/4] Installing dependencies...
call venv\Scripts\activate.bat
pip install --upgrade pip >nul
pip install -r requirements.txt
echo.

REM Create audit-reports directory if it doesn't exist
if not exist "audit-reports" (
    echo [4/4] Creating reports directory...
    mkdir audit-reports
) else (
    echo [4/4] Reports directory already exists
)
echo.

echo ========================================
echo Installation complete!
echo.
echo To run the audit tool:
echo   1. Configure credentials in .env file:
echo      copy .env.example .env
echo      # Edit .env with your settings
echo   2. Run the audit:
echo      venv\Scripts\activate
echo      python -m src.cli --ssh-user admin
echo      # Password will be prompted interactively
echo.
echo Or use the quick command:
echo   scripts\run_audit.bat --ssh-user admin
echo ========================================
pause
