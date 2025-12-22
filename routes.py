from flask import render_template, request, redirect, url_for, flash, jsonify, send_file
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.utils import secure_filename
from datetime import datetime
import logging
import json
import io
import os
import tempfile
from models import User, ScanResult, DecryptionAttempt

# These variables will be initialized by the init_routes function
app = None
db = None
login_manager = None 
ransomware_detector = None
decryption_engine = None

def init_routes(flask_app, database, login_mgr, detector, decryptor):
    global app, db, login_manager, ransomware_detector, decryption_engine
    app = flask_app
    db = database
    login_manager = login_mgr
    ransomware_detector = detector
    decryption_engine = decryptor
    
    # Set up login manager user loader
    @login_manager.user_loader
    def load_user(id):
        return db.session.get(User, int(id))
    
    # Register all the routes
    register_routes()
    
    return app

def register_routes():
    @app.route('/')
    @login_required
    def dashboard():
        scans = ScanResult.query.filter_by(user_id=current_user.id).order_by(ScanResult.timestamp.desc()).all()
        return render_template('dashboard.html', scans=scans)

    @app.route('/report/<int:scan_id>')
    @login_required
    def view_report(scan_id):
        scan = ScanResult.query.filter_by(id=scan_id, user_id=current_user.id).first_or_404()
        return render_template('report.html', scan=scan)

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if request.method == 'POST':
            user = User.query.filter_by(username=request.form['username']).first()
            if user and user.check_password(request.form['password']):
                login_user(user)
                return redirect(url_for('dashboard'))
            flash('Invalid username or password')
        return render_template('login.html')

    @app.route('/register', methods=['GET', 'POST'])
    def register():
        if request.method == 'POST':
            if User.query.filter_by(username=request.form['username']).first():
                flash('Username already exists')
                return redirect(url_for('register'))

            user = User(
                username=request.form['username'],
                email=request.form['email']
            )
            user.set_password(request.form['password'])

            db.session.add(user)
            db.session.commit()

            flash('Registration successful')
            return redirect(url_for('login'))
        return render_template('register.html')

    @app.route('/logout')
    @login_required
    def logout():
        logout_user()
        return redirect(url_for('login'))

    @app.route('/scan', methods=['POST'])
    @login_required
    def scan():
        if 'file' not in request.files:
            return {'error': 'No file provided'}, 400

        file = request.files['file']
        if file.filename == '':
            return {'error': 'No file selected'}, 400

        try:
            filename = secure_filename(file.filename)
            file_content = file.read()

            # Log file details
            logging.info(f"Processing file: {filename}, size: {len(file_content)} bytes")

            result = ransomware_detector.predict(file_content)

            try:
                scan_result = ScanResult(
                    user_id=current_user.id,
                    filename=filename,
                    timestamp=datetime.utcnow(),
                    is_ransomware=result['is_ransomware'],
                    confidence=result['confidence'],
                    file_size=result['file_size'],
                    file_type=result['file_type'],
                    entropy_score=result['entropy_score'],
                    contains_executable=result['contains_executable'],
                    encryption_detected=result['encryption_detected'],
                    analysis_details=result['analysis_details']
                )

                db.session.add(scan_result)
                db.session.commit()

                # Include the scan_id in the response for redirect to detailed report
                return {
                    'filename': filename,
                    'is_ransomware': result['is_ransomware'],
                    'confidence': result['confidence'],
                    'scan_id': scan_result.id,
                    'encryption_detected': result['encryption_detected']
                }

            except Exception as db_error:
                logging.error(f"Database error while saving scan result: {str(db_error)}")
                return {
                    'filename': filename,
                    'is_ransomware': result['is_ransomware'],
                    'confidence': result['confidence'],
                    'encryption_detected': result['encryption_detected']
                }

        except Exception as e:
            logging.error(f"Scan failed: {str(e)}")
            return {'error': f'Scan failed: {str(e)}'}, 500

    @app.route('/decrypt', methods=['GET', 'POST'])
    @login_required
    def decrypt_file():
        if request.method == 'GET':
            scan_id = request.args.get('scan_id')
            if scan_id:
                scan = ScanResult.query.filter_by(id=scan_id, user_id=current_user.id).first_or_404()
                return render_template('decryption.html', scan=scan)
            return render_template('decryption.html')
        
        # POST request - process the file for decryption
        if 'file' not in request.files:
            return {'error': 'No file provided'}, 400

        file = request.files['file']
        scan_id = request.form.get('scan_id')
        processing_priority = request.form.get('processing_priority', 'balanced')
        
        if file.filename == '':
            return {'error': 'No file selected'}, 400

        # Validate file size (50MB limit)
        file_content = file.read()
        if len(file_content) > 50 * 1024 * 1024:  # 50MB in bytes
            return {'error': 'File too large. Maximum size is 50MB.'}, 400

        try:
            filename = secure_filename(file.filename)
            
            # Create a new decryption attempt entry
            decryption_attempt = DecryptionAttempt(
                user_id=current_user.id,
                scan_result_id=scan_id if scan_id else None,
                filename=f"decryption_attempt_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{filename}",
                original_filename=filename,
                status="processing"
            )
            
            db.session.add(decryption_attempt)
            db.session.commit()
            
            # Log the decryption attempt
            logging.info(f"Starting decryption attempt for file: {filename} (ID: {decryption_attempt.id})")
            
            # Adjust strategy based on processing priority
            strategy_options = {}
            if processing_priority == 'thorough':
                strategy_options = {
                    'exhaustive_search': True,
                    'deep_analysis': True,
                    'timeout_multiplier': 2.0
                }
            elif processing_priority == 'fast':
                strategy_options = {
                    'exhaustive_search': False,
                    'deep_analysis': False,
                    'timeout_multiplier': 0.5
                }
            
            # Start the AI analysis process with strategy options
            analysis_result = decryption_engine.analyze_encryption(file_content)
            
            # Enhance strategy with priority options if available
            if strategy_options and 'strategy' in analysis_result:
                analysis_result['strategy'].update(strategy_options)
            
            # Update the attempt with analysis results
            decryption_attempt.decryption_strategy = json.dumps(analysis_result['strategy'])
            decryption_attempt.encryption_type_detected = analysis_result['encryption_type']
            db.session.commit()
            
            # Log analysis results
            logging.info(f"Encryption analysis completed for ID {decryption_attempt.id}: {analysis_result['encryption_type']}")
            
            # Attempt the actual decryption
            decryption_result = decryption_engine.attempt_decryption(
                file_content, 
                analysis_result['strategy']
            )
            
            # Update the decryption attempt with results
            decryption_attempt.status = "completed"
            decryption_attempt.success_level = decryption_result['success_level']
            decryption_attempt.confidence = decryption_result['confidence']
            decryption_attempt.result_message = decryption_result['message']
            decryption_attempt.encryption_key_found = decryption_result['key_found']
            decryption_attempt.decrypted_file_size = len(decryption_result['decrypted_content']) if decryption_result['decrypted_content'] else 0
            decryption_attempt.decryption_time = decryption_result['execution_time']
            decryption_attempt.analysis_details = json.dumps(decryption_result['details'])
            
            db.session.commit()
            
            # Return the decryption attempt ID for redirection
            return {
                'success': True,
                'decryption_id': decryption_attempt.id,
                'success_level': decryption_attempt.success_level
            }
        
        except Exception as e:
            logging.error(f"Decryption failed: {str(e)}")
            if 'decryption_attempt' in locals():
                decryption_attempt.status = "failed"
                decryption_attempt.error_details = str(e)
                db.session.commit()
                return {
                    'success': False,
                    'error': str(e),
                    'decryption_id': decryption_attempt.id
                }
            return {'error': f'Decryption failed: {str(e)}'}, 500

    @app.route('/decryption_report/<int:decryption_id>')
    @login_required
    def decryption_report(decryption_id):
        decryption = DecryptionAttempt.query.filter_by(id=decryption_id, user_id=current_user.id).first_or_404()
        return render_template('decryption_report.html', decryption=decryption)

    @app.route('/download_decrypted/<int:decryption_id>')
    @login_required
    def download_decrypted(decryption_id):
        decryption = DecryptionAttempt.query.filter_by(id=decryption_id, user_id=current_user.id).first_or_404()
        
        if decryption.success_level in ['full', 'partial']:
            # Retrieve the decrypted content
            decrypted_content = decryption_engine.get_decrypted_content(decryption_id)
            
            if decrypted_content:
                # Create a file-like object from the decrypted content
                file_obj = io.BytesIO(decrypted_content)
                
                # Create a filename for the decrypted file
                original_name, original_ext = os.path.splitext(decryption.original_filename)
                decrypted_filename = f"{original_name}_decrypted{original_ext}"
                
                # Send the file to the user
                return send_file(
                    file_obj,
                    as_attachment=True,
                    download_name=decrypted_filename,
                    mimetype='application/octet-stream'
                )
        
        flash('No decrypted content available for download')
        return redirect(url_for('decryption_report', decryption_id=decryption_id))

    @app.route('/decryption_history')
    @login_required
    def decryption_history():
        decryptions = DecryptionAttempt.query.filter_by(user_id=current_user.id).order_by(DecryptionAttempt.timestamp.desc()).all()
        return render_template('decryption_history.html', decryptions=decryptions)
