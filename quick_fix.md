# Quick Fix for Import Error

Follow these steps to fix the circular import error:

## Step 1: Fix main.py

Open `main.py` in a text editor and modify it to look like this:

```python
import os
import logging
import json
from datetime import datetime

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_file
from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase
import tempfile
from io import BytesIO

# Set up logging
logging.basicConfig(level=logging.DEBUG)

# Create database base class
class Base(DeclarativeBase):
    pass

# Initialize SQLAlchemy with the base class
db = SQLAlchemy(model_class=Base)

# Create Flask application
app = Flask(__name__)

# Set up configuration
app.secret_key = os.environ.get("SESSION_SECRET", "development_secret_key")
# Use SQLite by default for local deployment, but allow PostgreSQL with environment variable
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "sqlite:///ransomware_detector.db")
# Only use these options with PostgreSQL
if os.environ.get("DATABASE_URL") and "postgresql" in os.environ.get("DATABASE_URL", ""):
    app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
        "pool_recycle": 300,
        "pool_pre_ping": True,
    }
app.config["UPLOAD_FOLDER"] = os.path.join(os.path.dirname(os.path.abspath(__file__)), "uploads")
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

# Initialize SQLAlchemy with the app
db.init_app(app)

# Set up Login Manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

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

# Import models after setting up db to avoid circular imports
with app.app_context():
    # First import the models
    from models import User, ScanResult, DecryptionAttempt
    # Then create tables
    db.create_all()

# Initialize ML detector and decryption engine
from ml_detector import RansomwareDetector
from decryption_engine import DecryptionEngine

ransomware_detector = RansomwareDetector()
decryption_engine = DecryptionEngine()

# Import routes AFTER models and initialize everything
from routes import init_routes
init_routes(app, db, login_manager, ransomware_detector, decryption_engine)

# Start the app
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
```

## Step 2: Fix models.py

Make sure your `models.py` doesn't import from `main.py`. It should look like this:

```python
from datetime import datetime
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
import json

# Import db from the main application
from main import db

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256))
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class ScanResult(db.Model):
    # Your ScanResult model code here
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False)
    is_ransomware = db.Column(db.Boolean, nullable=False)
    confidence = db.Column(db.Float, nullable=False)
    file_size = db.Column(db.Integer, nullable=False)
    file_type = db.Column(db.String(50))
    entropy_score = db.Column(db.Float)
    contains_executable = db.Column(db.Boolean)
    encryption_detected = db.Column(db.Boolean)
    analysis_details = db.Column(db.Text)  # JSON string of additional analysis details

class DecryptionAttempt(db.Model):
    # Your DecryptionAttempt model code here
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    scan_result_id = db.Column(db.Integer, db.ForeignKey('scan_result.id'), nullable=True)
    filename = db.Column(db.String(255), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    status = db.Column(db.String(50), default="pending", nullable=False)  # pending, processing, completed, failed
    decryption_strategy = db.Column(db.Text)  # JSON string with the strategy details
    success_level = db.Column(db.String(20), nullable=True)  # full, partial, failed
    confidence = db.Column(db.Float, nullable=True)
    result_message = db.Column(db.Text, nullable=True)
    error_details = db.Column(db.Text, nullable=True)
    decrypted_file_size = db.Column(db.Integer, nullable=True)
    decryption_time = db.Column(db.Float, nullable=True)  # in seconds
    encryption_type_detected = db.Column(db.String(100), nullable=True)
    encryption_key_found = db.Column(db.Boolean, default=False)
    analysis_details = db.Column(db.Text, nullable=True)  # JSON string with detailed analysis
    
    def get_analysis_details(self):
        """Return the analysis details as a dictionary"""
        if not self.analysis_details:
            return {}
        try:
            return json.loads(self.analysis_details)
        except:
            return {}
    
    def get_decryption_strategy(self):
        """Return the decryption strategy as a dictionary"""
        if not self.decryption_strategy:
            return {}
        try:
            return json.loads(self.decryption_strategy)
        except:
            return {}
```

## Alternative Fix: Use a Factory Pattern

If the above fix doesn't work, you can use a factory pattern approach:

1. Create a new file called `app_factory.py` with this content:

```python
import os
import logging
import json
from datetime import datetime

from flask import Flask
from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase

# Set up logging
logging.basicConfig(level=logging.DEBUG)

# Create database base class
class Base(DeclarativeBase):
    pass

# Initialize SQLAlchemy with the base class
db = SQLAlchemy(model_class=Base)
login_manager = LoginManager()

def create_app():
    # Create Flask application
    app = Flask(__name__)
    
    # Set up configuration
    app.secret_key = os.environ.get("SESSION_SECRET", "development_secret_key")
    app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "sqlite:///ransomware_detector.db")
    if os.environ.get("DATABASE_URL") and "postgresql" in os.environ.get("DATABASE_URL", ""):
        app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
            "pool_recycle": 300,
            "pool_pre_ping": True,
        }
    app.config["UPLOAD_FOLDER"] = os.path.join(os.path.dirname(os.path.abspath(__file__)), "uploads")
    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
    
    # Initialize SQLAlchemy with the app
    db.init_app(app)
    
    # Set up Login Manager
    login_manager.init_app(app)
    login_manager.login_view = 'login'
    
    return app
```

2. Then modify `main.py` to use the factory:

```python
from app_factory import create_app, db, login_manager
import logging
import json

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

# Import models
with app.app_context():
    from models import User, ScanResult, DecryptionAttempt
    db.create_all()

# Initialize ML detector and decryption engine
from ml_detector import RansomwareDetector
from decryption_engine import DecryptionEngine

ransomware_detector = RansomwareDetector()
decryption_engine = DecryptionEngine()

# Import routes
from routes import init_routes
init_routes(app, db, login_manager, ransomware_detector, decryption_engine)

# Start the app
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
```

3. And modify `models.py` to import from app_factory:

```python
from app_factory import db
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import json

class User(UserMixin, db.Model):
    # User model code...
```

## Choose the approach that works best for your application structure.