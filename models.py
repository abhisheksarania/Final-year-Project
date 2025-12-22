from app_factory import db
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import json

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
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False)
    is_ransomware = db.Column(db.Boolean, nullable=False)
    confidence = db.Column(db.Float, nullable=False)
    # Detailed analysis fields
    file_size = db.Column(db.Integer, nullable=False)
    file_type = db.Column(db.String(50))
    entropy_score = db.Column(db.Float)
    contains_executable = db.Column(db.Boolean)
    encryption_detected = db.Column(db.Boolean)
    analysis_details = db.Column(db.Text)  # JSON string of additional analysis details

class DecryptionAttempt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    scan_result_id = db.Column(db.Integer, db.ForeignKey('scan_result.id'), nullable=True)
    filename = db.Column(db.String(255), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    status = db.Column(db.String(50), default="pending", nullable=False)  # pending, processing, completed, failed
    decryption_strategy = db.Column(db.Text)  # JSON string with the strategy details
    
    # Outcomes
    success_level = db.Column(db.String(20), nullable=True)  # full, partial, failed
    confidence = db.Column(db.Float, nullable=True)
    
    # Results and error information
    result_message = db.Column(db.Text, nullable=True)
    error_details = db.Column(db.Text, nullable=True)
    
    # Results metadata
    decrypted_file_size = db.Column(db.Integer, nullable=True)
    decryption_time = db.Column(db.Float, nullable=True)  # in seconds
    
    # Additional analysis details
    encryption_type_detected = db.Column(db.String(100), nullable=True)
    encryption_key_found = db.Column(db.Boolean, default=False)
    analysis_details = db.Column(db.Text, nullable=True)  # JSON string with detailed analysis
    
    def get_analysis_details(self):
        """Return the analysis details as a dictionary"""
        if self.analysis_details:
            try:
                return json.loads(self.analysis_details)
            except json.JSONDecodeError:
                return {}
        return {}
    
    def get_decryption_strategy(self):
        """Return the decryption strategy as a dictionary"""
        if self.decryption_strategy:
            try:
                return json.loads(self.decryption_strategy)
            except json.JSONDecodeError:
                return {}
        return {}
