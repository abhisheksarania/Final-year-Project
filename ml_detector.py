import numpy as np
from sklearn.ensemble import RandomForestClassifier
import math
import logging
import struct
from io import BytesIO
import zlib
import json
import time

class RansomwareDetector:
    def __init__(self):
        self.model = RandomForestClassifier(n_estimators=100)
        self._initialize_model()

    def _initialize_model(self):
        """Initialize a basic model with some simple rules"""
        # In production, this would load from a pre-trained model
        # For now, create a simple model that can handle both classes
        X_dummy = [[0, 0, 0, 0, 0], [1, 1, 1, 1, 1]]  # Two examples for two classes
        y_dummy = [0, 1]  # 0 for clean, 1 for ransomware
        self.model.fit(X_dummy, y_dummy)
        logging.info("ML model initialized with dummy data for both classes")

    def _calculate_entropy(self, data):
        """Calculate Shannon entropy of byte stream"""
        if not data:
            return 0
        entropy = 0
        for x in range(256):
            p_x = data.count(x)/len(data)
            if p_x > 0:
                entropy += -p_x*math.log2(p_x)
        return entropy

    def _is_pe_file(self, data):
        """Check if the file is a PE (Windows executable)"""
        try:
            return data.startswith(b'MZ') and len(data) > 64
        except:
            return False

    def _is_zip_file(self, data):
        """Check if the file is a ZIP archive"""
        try:
            return data.startswith(b'PK\x03\x04')
        except:
            return False

    def _detect_encryption(self, data, entropy):
        """Detect possible encryption based on entropy and patterns"""
        high_entropy = entropy > 7.0
        random_distribution = 0.45 < (data.count(b'\x00')/len(data)) < 0.55
        return high_entropy and random_distribution

    def _get_file_type(self, content):
        """Determine file type based on magic numbers and patterns"""
        if self._is_pe_file(content):
            return "Windows Executable (PE)"
        elif self._is_zip_file(content):
            return "ZIP Archive"
        elif content.startswith(b'%PDF'):
            return "PDF Document"
        elif content.startswith(b'\x89PNG'):
            return "PNG Image"
        else:
            return "Unknown Binary" if any(x < 32 and x != 9 and x != 10 and x != 13 for x in content[:1000]) else "Text File"

    def _calculate_byte_frequency(self, content):
        """Calculate frequency distribution of bytes"""
        freqs = {}
        for i in range(256):
            freqs[i] = 0
        
        for byte in content:
            freqs[byte] += 1
            
        return {k: v/len(content) for k, v in freqs.items() if v > 0}
    
    def _calculate_encryption_percentage(self, entropy, compression_ratio, byte_distribution):
        """
        Calculate an estimated percentage of encryption in the file
        based on entropy, compression ratio, and byte distribution
        """
        # Factors that indicate encryption
        # 1. High entropy (max 8.0 for bytes)
        entropy_factor = min(entropy / 8.0, 1.0)
        
        # 2. Compression ratio close to 1.0 (can't compress encrypted data further)
        # Lower is better for this metric (1.0 means no compression possible)
        compression_factor = min(2.0 - compression_ratio, 1.0)
        
        # 3. Uniform byte distribution (all bytes appear with similar frequency)
        # Calculate standard deviation of frequencies
        values = list(byte_distribution.values())
        std_dev = np.std(values) if values else 0
        # Perfect uniformity would have std_dev = 0
        distribution_factor = 1.0 - min(std_dev * 20, 1.0)  # Scale up for sensitivity
        
        # 4. Calculate weighted average (different weights for different indicators)
        weights = [0.5, 0.2, 0.3]  # Entropy is most important
        overall = (
            weights[0] * entropy_factor + 
            weights[1] * compression_factor + 
            weights[2] * distribution_factor
        )
        
        return overall * 100  # Convert to percentage
        
    def _extract_features(self, file_content):
        """Extract features from file content"""
        try:
            # Convert to bytes if needed
            if isinstance(file_content, BytesIO):
                content = file_content.getvalue()
            elif isinstance(file_content, str):
                content = file_content.encode('utf-8')
            else:
                content = file_content

            # Feature 1: Entropy
            entropy = self._calculate_entropy(content)

            # Feature 2: Percentage of null bytes
            null_byte_ratio = content.count(0) / len(content)

            # Feature 3: Ratio of printable characters
            printable_chars = sum(32 <= x <= 126 for x in content)
            printable_ratio = printable_chars / len(content)

            # Feature 4: Compression ratio (high in encrypted/compressed files)
            compressed = zlib.compress(content)
            compression_ratio = len(compressed) / len(content)

            # Feature 5: File type indicator
            is_binary = self._is_pe_file(content) or self._is_zip_file(content)

            features = [entropy, null_byte_ratio, printable_ratio, compression_ratio, float(is_binary)]
            logging.debug(f"Extracted features: {features}")

            # Additional analysis for detailed report
            file_type = self._get_file_type(content)
            encryption_detected = self._detect_encryption(content, entropy)
            
            # Calculate byte frequency distribution
            byte_distribution = self._calculate_byte_frequency(content)
            
            # Calculate encryption percentage estimate
            encryption_percentage = self._calculate_encryption_percentage(
                entropy, compression_ratio, byte_distribution
            )

            # Determine potential encryption type if encryption is detected
            encryption_type = self._analyze_encryption_type(content, entropy) if encryption_detected else "None"
            
            # Generate byte distribution for visualization
            byte_dist_data = {
                'labels': list(range(256)), 
                'data': [byte_distribution.get(i, 0) for i in range(256)]
            }
            
            # Calculate encryption metrics for visualization
            encryption_metrics = {
                'labels': ['Encrypted', 'Non-Encrypted'],
                'data': [encryption_percentage, 100 - encryption_percentage]
            }

            # Store detailed analysis
            self.detailed_analysis = {
                'file_size': len(content),
                'file_type': file_type,
                'entropy_score': entropy,
                'contains_executable': is_binary,
                'encryption_detected': encryption_detected,
                'encryption_percentage': round(encryption_percentage, 2),
                'analysis_details': json.dumps({
                    'null_byte_ratio': null_byte_ratio,
                    'printable_ratio': printable_ratio,
                    'compression_ratio': compression_ratio,
                    'potential_encryption_type': encryption_type,
                    'entropy_analysis': {
                        'value': entropy,
                        'risk_level': 'High' if entropy > 7.0 else 'Medium' if entropy > 6.0 else 'Low'
                    },
                    'byte_distribution': byte_dist_data,
                    'encryption_metrics': encryption_metrics
                })
            }

            return features

        except Exception as e:
            logging.error(f"Feature extraction failed: {str(e)}")
            raise

    def _analyze_encryption_type(self, content, entropy):
        """Analyze the potential encryption type"""
        # This is a simplified version - in a real system, this would be more sophisticated
        if entropy > 7.8:  # Very high entropy often indicates strong encryption like AES
            return "Strong encryption (possibly AES, RSA)"
        elif entropy > 7.0:
            return "Medium-strength encryption (possibly RC4, DES)"
        elif entropy > 6.5:
            return "Simple encryption or encoding (possibly XOR, Base64)"
        else:
            return "Unknown or weak encryption"

    def predict(self, file_content):
        """Predict if a file is ransomware"""
        try:
            features = self._extract_features(file_content)
            # Get prediction and probability
            prediction = self.model.predict([features])[0]
            probabilities = self.model.predict_proba([features])[0]
            # Get confidence for the predicted class
            confidence = probabilities[1] if prediction == 1 else probabilities[0]

            logging.info(f"Prediction: {prediction}, Confidence: {confidence}")

            # Combine prediction with detailed analysis
            result = {
                'is_ransomware': bool(prediction),
                'confidence': float(confidence)
            }
            result.update(self.detailed_analysis)
            return result

        except Exception as e:
            logging.error(f"Prediction failed: {str(e)}")
            raise
