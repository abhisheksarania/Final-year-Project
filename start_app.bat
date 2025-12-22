@echo off
echo ===================================================
echo  Ransomware Detection and Decryption Application
echo ===================================================
echo.

REM Check for Python installation
python --version > nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python is not installed or not in your PATH.
    echo Please install Python 3.8 or higher from https://www.python.org/downloads/
    echo Make sure to check "Add Python to PATH" during installation.
    echo.
    pause
    exit /b 1
)

echo [INFO] Python found. Checking dependencies...

REM Create uploads folder if it doesn't exist
if not exist "uploads" (
    echo [INFO] Creating uploads directory...
    mkdir uploads
)

REM Check if virtual environment exists, create if it doesn't
if not exist "venv" (
    echo [INFO] Setting up virtual environment...
    python -m venv venv
    if %errorlevel% neq 0 (
        echo [ERROR] Failed to create virtual environment.
        echo Please make sure you have the venv module installed.
        echo Try running: pip install virtualenv
        echo.
        pause
        exit /b 1
    )
)

REM Activate virtual environment
echo [INFO] Activating virtual environment...
call venv\Scripts\activate.bat

REM Install required packages
echo [INFO] Installing required packages...
pip install flask flask-login flask-sqlalchemy werkzeug gunicorn numpy scikit-learn email-validator

REM Create database tables if they don't exist
echo [INFO] Setting up SQLite database...
python -c "from main import app, db; app.app_context().push(); db.create_all()"

REM Start the application
echo.
echo ===================================================
echo  Application is now running!
echo  Open your browser and go to: http://localhost:5000
echo ===================================================
echo.
echo [INFO] Press Ctrl+C to stop the server when you're done
echo.

REM Start the application with a more visible error message
python main.py

REM If Python fails to start, show an error
if %errorlevel% neq 0 (
    echo.
    echo [ERROR] Failed to start the application.
    echo Please check the error message above.
    echo.
    pause
)