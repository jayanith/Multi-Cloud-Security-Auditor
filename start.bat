@echo off
echo ========================================
echo  Multi-Cloud Security Auditor
echo ========================================
echo.

REM Check if virtual environment exists
if exist venv\ (
    echo Activating virtual environment...
    call venv\Scripts\activate
) else (
    echo WARNING: Virtual environment not found!
    echo Run setup.bat first to create it.
    echo.
    pause
    exit /b 1
)

echo Starting application...
python run.py

if errorlevel 1 (
    echo.
    echo ERROR: Failed to start application
    echo Make sure dependencies are installed: pip install -r requirements.txt
    pause
)
