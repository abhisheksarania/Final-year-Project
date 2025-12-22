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