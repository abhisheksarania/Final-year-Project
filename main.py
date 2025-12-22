import os
import logging
import json
from datetime import datetime
import tempfile
from io import BytesIO

from flask import render_template, request, redirect, url_for, flash, jsonify, send_file
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.utils import secure_filename

# Import from our app factory
from app_factory import create_app, db, login_manager

# Set up logging
logging.basicConfig(level=logging.DEBUG)

# Create the app
app = create_app()

# Add custom filter for parsing JSON
@app.template_filter('fromjson')
def fromjson_filter(value):
    if not value:
        return {}
    try:
        return json.loads(value)
    except Exception as e:
        logging.error(f"Error parsing JSON: {str(e)}")
        return {}

# Import models and create tables
with app.app_context():
    from models import User, ScanResult, DecryptionAttempt
    db.create_all()

# Initialize ML detector and decryption engine
from ml_detector import RansomwareDetector
from decryption_engine import DecryptionEngine

ransomware_detector = RansomwareDetector()
decryption_engine = DecryptionEngine()

# Import routes and initialize
from routes import init_routes
init_routes(app, db, login_manager, ransomware_detector, decryption_engine)

# Start the app
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
