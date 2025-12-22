# Ransomware Detection and Decryption Platform

An advanced AI-powered ransomware detection and file decryption platform that provides comprehensive file recovery capabilities.

## Features

- AI-powered detection of ransomware-encrypted files
- Interactive visualization of encryption metrics with pie charts
- Real-time decryption workflow tracking
- Multiple processing priority modes (fast, balanced, thorough)
- Detailed reporting of decryption attempts
- Visual indicators of decryption success

## Requirements

- Python 3.8 or higher
- PostgreSQL database
- Modern web browser

## How to Download and Run the Application

### Downloading the Application

1. Use one of these methods to download the application:
   - **On Replit**: Click on the three dots menu in the Replit interface and select "Download as ZIP"
   - **On GitHub**: Click on the "Code" button and select "Download ZIP"

2. Extract the ZIP file to a folder on your computer.
   - **Windows**: Right-click the ZIP file and select "Extract All..."
   - **macOS**: Double-click the ZIP file
   - **Linux**: Run `unzip filename.zip` in the terminal

### Running the Application (Detailed Instructions)

I've made the application very easy to run! You don't need to install PostgreSQL or any other database server. The application is now configured to use SQLite, which is a file-based database included with Python.

#### Windows Users

1. Ensure you have Python 3.8 or newer installed
   - Download from [python.org](https://www.python.org/downloads/)
   - **IMPORTANT**: During installation, check the box "Add Python to PATH"
   - To verify installation, open Command Prompt and type: `python --version`

2. Navigate to the extracted folder in File Explorer

3. Double-click the `start_app.bat` file
   - If you get a security warning, click "Run" or "More info" → "Run anyway"
   - A Command Prompt window will open and show the installation progress
   - The script will automatically:
     - Create a virtual environment
     - Install all required packages
     - Set up the SQLite database
     - Start the application

4. When you see "Application is now running!" in the Command Prompt, open your web browser and go to:
   ```
   http://localhost:5000
   ```

5. To stop the application, press Ctrl+C in the Command Prompt window

#### macOS / Linux Users

1. Ensure you have Python 3.8 or newer installed
   - **macOS**: Install via [python.org](https://www.python.org/downloads/) or Homebrew: `brew install python`
   - **Ubuntu/Debian**: `sudo apt install python3 python3-venv python3-pip`
   - **Fedora**: `sudo dnf install python3 python3-pip`
   - To verify installation, open Terminal and type: `python3 --version`

2. Open Terminal and navigate to the extracted folder:
   ```bash
   cd path/to/extracted/folder
   ```

3. Make the start script executable:
   ```bash
   chmod +x start.sh
   ```

4. Run the script:
   ```bash
   ./start.sh
   ```
   - The script will automatically:
     - Create a virtual environment
     - Install all required packages
     - Set up the SQLite database
     - Start the application

5. When you see "Application is now running!" in the Terminal, open your web browser and go to:
   ```
   http://localhost:5000
   ```

6. To stop the application, press Ctrl+C in the Terminal

### Troubleshooting Common Issues

#### "Python is not installed or not in PATH"
- Make sure Python is installed and added to your PATH
- For Windows, you may need to reinstall Python and check "Add Python to PATH"

#### "Failed to create virtual environment"
- Windows: Run Command Prompt as Administrator and try again
- Linux/macOS: Install the venv module: `sudo apt install python3-venv` (Ubuntu/Debian)

#### "ModuleNotFoundError: No module named 'X'"
- The startup script should install all dependencies automatically
- If you see this error, manually install the missing package:
  ```
  pip install X  # Replace X with the package name
  ```

#### "Permission denied" (Linux/macOS)
- Make sure the script is executable: `chmod +x start.sh`

#### "Address already in use" error
- Another application is using port 5000
- Stop the other application or modify the port in main.py

## First-Time Setup

1. When you first access the application, you'll need to register an account.
2. Click on "Register" and create your user account.
3. Log in with your credentials.

## Using the Application

### Scanning Files

1. From the dashboard, click on "Scan File"
2. Upload a file to analyze
3. View the detailed report showing encryption detection metrics

### Decryption Workflow

1. Upload a potentially encrypted file
2. Select processing priority (fast, balanced, thorough)
3. Monitor real-time decryption progress
4. View detailed decryption report
5. Download decrypted files if recovery was successful

## Troubleshooting

- Ensure Python 3.8+ is installed and in your system PATH
- Check database connection settings
- Verify that all required packages are installed
- For Windows users: Run the application as administrator if needed
- For Linux/Mac users: Ensure proper permissions are set

## License

This project is licensed under the MIT License - see the LICENSE file for details.