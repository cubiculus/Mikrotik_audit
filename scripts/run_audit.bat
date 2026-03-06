@echo off
REM Quick run script for MikroTik Audit Tool (Windows)
REM Usage: scripts\run_audit.bat --ssh-user admin --ssh-pass your_password

if not exist "venv" (
    echo [ERROR] Virtual environment not found!
    echo Run: scripts\install.bat
    pause
    exit /b 1
)

call venv\Scripts\activate.bat
python -m src.cli %*
