#!/bin/bash

echo "==================================================="
echo " Ransomware Detection and Decryption Application"
echo "==================================================="
echo ""

# Check for Python installation
if ! command -v python3 &> /dev/null; then
    echo "[ERROR] Python 3 is not installed or not in PATH."
    echo "Please install Python 3.8 or higher from https://www.python.org/downloads/"
    echo "On Ubuntu/Debian, you can run: sudo apt install python3 python3-venv python3-pip"
    echo "On macOS with Homebrew, you can run: brew install python"
    exit 1
fi

echo "[INFO] Python found. Checking dependencies..."

# Create uploads folder if it doesn't exist
if [ ! -d "uploads" ]; then
    echo "[INFO] Creating uploads directory..."
    mkdir -p uploads
fi

# Check if virtual environment exists, create if it doesn't
if [ ! -d "venv" ]; then
    echo "[INFO] Setting up virtual environment..."
    python3 -m venv venv
    if [ $? -ne 0 ]; then
        echo "[ERROR] Failed to create virtual environment."
        echo "Please make sure you have the venv module installed."
        echo "On Ubuntu/Debian, you can run: sudo apt install python3-venv"
        echo "On macOS, you can run: pip3 install virtualenv"
        exit 1
    fi
fi

# Activate virtual environment
echo "[INFO] Activating virtual environment..."
source venv/bin/activate

# Install required packages
echo "[INFO] Installing required packages..."
pip install flask flask-login flask-sqlalchemy werkzeug gunicorn numpy scikit-learn email-validator

# Create database tables if they don't exist
echo "[INFO] Setting up SQLite database..."
python -c "from main import app, db; app.app_context().push(); db.create_all()"

# Start the application
echo ""
echo "==================================================="
echo " Application is now running!"
echo " Open your browser and go to: http://localhost:5000"
echo "==================================================="
echo ""
echo "[INFO] Press Ctrl+C to stop the server when you're done"
echo ""

# Start the application and handle errors
python main.py
if [ $? -ne 0 ]; then
    echo ""
    echo "[ERROR] Failed to start the application."
    echo "Please check the error message above."
    echo ""
fi