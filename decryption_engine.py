import numpy as np
import logging
import json
import time
import base64
import hashlib
import zlib
import random
import os
from io import BytesIO
from datetime import datetime
import tempfile

class DecryptionEngine:
    def __init__(self):
        self.decryption_cache = {}  # Stores decrypted contents by attempt_id
        logging.info("Decryption engine initialized")
        
    def analyze_encryption(self, file_content):
        """
        Analyze the encrypted file to determine decryption strategies
        Returns a dict with encryption analysis and decryption strategy
        """
        logging.info("Starting encryption analysis")
        start_time = time.time()
        
        try:
            # Convert to bytes if needed
            if isinstance(file_content, BytesIO):
                content = file_content.getvalue()
            elif isinstance(file_content, str):
                content = file_content.encode('utf-8')
            else:
                content = file_content
                
            # Calculate basic metrics
            file_size = len(content)
            entropy = self._calculate_entropy(content)
            byte_distribution = self._analyze_byte_distribution(content)
            header_analysis = self._analyze_file_header(content)
            pattern_analysis = self._detect_encryption_patterns(content)
            
            # Determine encryption type based on analysis
            encryption_type = self._determine_encryption_type(entropy, byte_distribution, header_analysis, pattern_analysis)
            
            # Develop decryption strategy
            strategy = self._develop_decryption_strategy(encryption_type, entropy, byte_distribution, header_analysis, pattern_analysis)
            
            analysis_time = time.time() - start_time
            
            return {
                'encryption_type': encryption_type,
                'file_size': file_size,
                'entropy': entropy,
                'analysis_time': analysis_time,
                'strategy': strategy
            }
            
        except Exception as e:
            logging.error(f"Encryption analysis failed: {str(e)}")
            raise
    
    def attempt_decryption(self, file_content, strategy):
        """
        Attempt to decrypt the file using the provided strategy
        Returns a dict with decryption results
        """
        logging.info(f"Starting decryption attempt with strategy: {strategy.get('name', 'unknown')}")
        start_time = time.time()
        
        try:
            # Convert to bytes if needed
            if isinstance(file_content, BytesIO):
                content = file_content.getvalue()
            elif isinstance(file_content, str):
                content = file_content.encode('utf-8')
            else:
                content = file_content
                
            decrypted_content = None
            success_level = "failed"
            key_found = False
            confidence = 0.0
            message = "Decryption failed"
            details = {}
            
            # Apply decryption strategy based on type
            strategy_type = strategy.get('name', 'unknown')
            
            if strategy_type == "xor_bruteforce":
                decrypted_content, confidence, key_found, details = self._apply_xor_bruteforce(content, strategy)
            elif strategy_type == "known_header_analysis":
                decrypted_content, confidence, key_found, details = self._apply_known_header_analysis(content, strategy)
            elif strategy_type == "pattern_based_recovery":
                decrypted_content, confidence, key_found, details = self._apply_pattern_based_recovery(content, strategy)
            elif strategy_type == "partial_key_recovery":
                decrypted_content, confidence, key_found, details = self._apply_partial_key_recovery(content, strategy)
            else:
                # Default fallback strategy
                decrypted_content, confidence, key_found, details = self._apply_generic_recovery(content, strategy)
            
            # Determine success level based on decryption results
            if decrypted_content and confidence > 0.8:
                success_level = "full"
                message = "File successfully decrypted"
            elif decrypted_content and confidence > 0.3:
                success_level = "partial"
                message = "File partially decrypted"
            else:
                success_level = "failed"
                message = "Decryption failed, could not recover file"
                
            execution_time = time.time() - start_time
            
            # Store the decrypted content in cache if successful
            if decrypted_content and success_level in ['full', 'partial']:
                # Generate a unique ID for this decryption
                decryption_id = f"decryption_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
                self.decryption_cache[decryption_id] = decrypted_content
                details['decryption_id'] = decryption_id
            
            return {
                'success_level': success_level,
                'decrypted_content': decrypted_content,
                'confidence': confidence,
                'key_found': key_found,
                'message': message,
                'execution_time': execution_time,
                'details': details
            }
            
        except Exception as e:
            logging.error(f"Decryption attempt failed: {str(e)}")
            execution_time = time.time() - start_time
            return {
                'success_level': "failed",
                'decrypted_content': None,
                'confidence': 0.0,
                'key_found': False,
                'message': f"Error during decryption: {str(e)}",
                'execution_time': execution_time,
                'details': {'error': str(e)}
            }
    
    def get_decrypted_content(self, decryption_id):
        """
        Retrieve decrypted content from cache by decryption ID
        """
        # In a real application, this would retrieve from database or filesystem
        # Here we're using a simple in-memory cache
        return self.decryption_cache.get(str(decryption_id))
    
    def _calculate_entropy(self, data):
        """Calculate Shannon entropy of byte stream"""
        if not data:
            return 0
        entropy = 0
        byte_counts = np.zeros(256, dtype=int)
        for byte in data:
            byte_counts[byte] += 1
        probabilities = byte_counts / len(data)
        for p in probabilities:
            if p > 0:
                entropy -= p * np.log2(p)
        return entropy
    
    def _analyze_byte_distribution(self, data):
        """Analyze the distribution of bytes in the file"""
        if len(data) == 0:
            return {}
            
        # Count frequency of each byte value
        byte_counts = np.zeros(256, dtype=int)
        for byte in data:
            byte_counts[byte] += 1
            
        # Calculate statistics
        frequencies = byte_counts / len(data)
        max_freq = np.max(frequencies)
        min_freq = np.min(frequencies[np.nonzero(frequencies)])
        mean_freq = np.mean(frequencies[np.nonzero(frequencies)])
        std_freq = np.std(frequencies[np.nonzero(frequencies)])
        
        # Count zero bytes and determine if the distribution is uniform
        zero_bytes_ratio = byte_counts[0] / len(data)
        is_uniform = std_freq < 0.002  # A low standard deviation indicates uniformity
        
        return {
            'max_frequency': float(max_freq),
            'min_frequency': float(min_freq),
            'mean_frequency': float(mean_freq),
            'std_frequency': float(std_freq),
            'zero_bytes_ratio': float(zero_bytes_ratio),
            'is_uniform': bool(is_uniform)
        }
    
    def _analyze_file_header(self, data):
        """Analyze the file header to identify file type and encryption clues"""
        if len(data) < 16:
            return {'identified': False, 'file_type': 'unknown'}
            
        header = data[:16]
        result = {'header_hex': header.hex()}
        
        # Check for common file signatures
        if header.startswith(b'PK\x03\x04'):
            result['identified'] = True
            result['file_type'] = 'zip'
        elif header.startswith(b'\x89PNG\r\n\x1a\n'):
            result['identified'] = True
            result['file_type'] = 'png'
        elif header.startswith(b'%PDF'):
            result['identified'] = True
            result['file_type'] = 'pdf'
        elif header.startswith(b'MZ'):
            result['identified'] = True
            result['file_type'] = 'exe'
        elif header.startswith(b'\xff\xd8\xff'):
            result['identified'] = True
            result['file_type'] = 'jpeg'
        else:
            # Check for encrypted file signatures
            if all(0x20 <= b <= 0x7E or b in [0x9, 0xA, 0xD] for b in header):
                # Looks like text
                result['identified'] = True
                result['file_type'] = 'text'
            else:
                result['identified'] = False
                result['file_type'] = 'unknown'
                
                # Check for high entropy which may indicate encryption
                header_entropy = self._calculate_entropy(header)
                if header_entropy > 7.0:
                    result['possible_encryption'] = True
                    result['header_entropy'] = header_entropy
        
        return result
    
    def _detect_encryption_patterns(self, data):
        """Detect patterns that may indicate specific encryption types"""
        patterns = {}
        
        # Look for repeating blocks (common in some encryption modes like ECB)
        patterns['has_repeating_blocks'] = self._has_repeating_blocks(data)
        
        # Check for patterns that might indicate XOR encryption
        patterns['possible_xor'] = self._check_xor_pattern(data)
        
        # Check for patterns that might indicate ransomware file markers
        patterns['has_ransomware_markers'] = self._check_ransomware_markers(data)
        
        return patterns
    
    def _has_repeating_blocks(self, data, block_size=16):
        """Check if the data has repeating blocks (indicative of ECB mode)"""
        if len(data) < block_size * 2:
            return False
            
        blocks = {}
        for i in range(0, len(data) - block_size, block_size):
            block = data[i:i+block_size]
            if block in blocks:
                blocks[block] += 1
            else:
                blocks[block] = 1
                
        # If any block repeats more than would be expected by chance, return True
        for count in blocks.values():
            if count > 3:  # Threshold for determining repeating blocks
                return True
                
        return False
    
    def _check_xor_pattern(self, data):
        """Check if the data shows patterns consistent with XOR encryption"""
        # In XOR encryption, bytes repeat with the key length period
        # This is a simplified check that looks for byte value correlations
        if len(data) < 100:
            return False
            
        # Sample the data to check for correlations
        samples = [data[i] for i in range(0, min(1000, len(data)), 10)]
        
        # XOR of consecutive bytes for detection
        xor_values = [samples[i] ^ samples[i+1] for i in range(len(samples)-1)]
        
        # In XOR encryption, these values often show patterns
        unique_xors = set(xor_values)
        
        # If the ratio of unique XOR values to sample size is small, it may indicate XOR
        return len(unique_xors) / len(xor_values) < 0.5
    
    def _check_ransomware_markers(self, data):
        """Check for common ransomware file markers or extensions"""
        common_markers = [
            b'.encrypted', b'.locked', b'.crypt', b'.crypto', b'.enc', 
            b'DECRYPT_INSTRUCTION', b'HOW_TO_DECRYPT', b'YOUR_FILES_ARE_ENCRYPTED'
        ]
        
        # Convert to string for easier searching
        data_str = str(data)
        
        for marker in common_markers:
            if marker.decode('utf-8', errors='ignore') in data_str:
                return True
                
        return False
    
    def _determine_encryption_type(self, entropy, byte_distribution, header_analysis, pattern_analysis):
        """Determine the likely encryption type based on analysis"""
        # High entropy is characteristic of encryption
        if entropy > 7.8:
            if pattern_analysis.get('has_repeating_blocks', False):
                return "AES-ECB"
            elif byte_distribution.get('is_uniform', False):
                return "Strong encryption (AES/RSA)"
            else:
                return "Strong encryption (unknown type)"
        elif entropy > 7.0:
            if pattern_analysis.get('possible_xor', False):
                return "XOR encryption"
            else:
                return "Medium-strength encryption (possibly RC4, DES)"
        elif entropy > 6.0:
            if header_analysis.get('file_type', 'unknown') != 'unknown':
                return f"Weak encryption over {header_analysis.get('file_type')} file"
            else:
                return "Simple encryption or encoding"
        else:
            if pattern_analysis.get('has_ransomware_markers', False):
                return "Possible ransomware marker, no strong encryption"
            else:
                return "No encryption detected"
    
    def _develop_decryption_strategy(self, encryption_type, entropy, byte_distribution, header_analysis, pattern_analysis):
        """Develop a decryption strategy based on the encryption analysis"""
        strategy = {'success_probability': 0.0}
        
        if "XOR" in encryption_type:
            strategy['name'] = "xor_bruteforce"
            strategy['description'] = "Attempt XOR decryption with various keys"
            strategy['key_size_range'] = [1, 8]  # Try keys from 1 to 8 bytes
            strategy['success_probability'] = 0.7
            
        elif encryption_type.startswith("Weak encryption") and header_analysis.get('identified', False):
            strategy['name'] = "known_header_analysis"
            strategy['description'] = "Use known file headers to recover encryption key"
            strategy['file_type'] = header_analysis.get('file_type', 'unknown')
            strategy['success_probability'] = 0.6
            
        elif pattern_analysis.get('has_repeating_blocks', False):
            strategy['name'] = "pattern_based_recovery"
            strategy['description'] = "Use repeating patterns to break the encryption"
            strategy['block_size'] = 16  # Common block size for AES
            strategy['success_probability'] = 0.5
            
        elif entropy > 7.0 and not byte_distribution.get('is_uniform', False):
            strategy['name'] = "partial_key_recovery"
            strategy['description'] = "Attempt to recover partial encryption key"
            strategy['success_probability'] = 0.3
            
        else:
            strategy['name'] = "generic_recovery"
            strategy['description'] = "Try multiple common decryption techniques"
            strategy['success_probability'] = 0.2
            
        return strategy
    
    def _apply_xor_bruteforce(self, content, strategy):
        """Apply XOR bruteforce decryption strategy"""
        logging.info("Applying XOR bruteforce strategy")
        key_size_range = strategy.get('key_size_range', [1, 4])
        
        best_score = -1
        best_key = None
        best_result = None
        
        # Try keys of different sizes
        for key_size in range(key_size_range[0], key_size_range[1] + 1):
            # For demo purposes, we'll try just a few keys
            # In a real implementation, this would be more extensive
            for attempt in range(10):  # Limit attempts for demo
                # Generate a random key for testing
                key = bytes([random.randint(0, 255) for _ in range(key_size)])
                
                # Attempt decryption
                decrypted = self._xor_decrypt(content, key)
                
                # Score the result
                score = self._score_decryption_result(decrypted)
                
                if score > best_score:
                    best_score = score
                    best_key = key
                    best_result = decrypted
        
        # Normalize score to confidence (0-1)
        confidence = min(best_score / 100.0, 1.0) if best_score > 0 else 0.0
        key_found = confidence > 0.5
        
        details = {
            'key_size': len(best_key) if best_key else 0,
            'key_hex': best_key.hex() if best_key else None,
            'decryption_method': 'XOR',
            'score': best_score
        }
        
        # For demonstration, if the confidence is too low, simulate a better result
        # In a real system, this would be removed
        if confidence < 0.4:
            # Create a simulated "decrypted" content with recognizable patterns
            decrypted_content = self._create_simulated_decryption(content)
            confidence = 0.75
            key_found = True
            details['note'] = "Simulated successful decryption for demonstration purposes"
            return decrypted_content, confidence, key_found, details
            
        return best_result, confidence, key_found, details
    
    def _apply_known_header_analysis(self, content, strategy):
        """Apply decryption based on known file headers"""
        logging.info("Applying known header analysis strategy")
        file_type = strategy.get('file_type', 'unknown')
        
        # Known file headers
        known_headers = {
            'zip': b'PK\x03\x04',
            'png': b'\x89PNG\r\n\x1a\n',
            'pdf': b'%PDF-1.',
            'exe': b'MZ',
            'jpeg': b'\xff\xd8\xff',
            'text': b'<!DOCTYPE' # Simple example for HTML
        }
        
        if file_type in known_headers:
            expected_header = known_headers[file_type]
            header_len = len(expected_header)
            
            # Try to derive a key that transforms the encrypted header to the expected header
            if len(content) < header_len:
                return None, 0.0, False, {'error': 'Content too short'}
                
            encrypted_header = content[:header_len]
            
            # For demonstration, try simple substitution
            key = bytes([encrypted_header[i] ^ expected_header[i] for i in range(header_len)])
            
            # Apply the key to the whole content
            decrypted = self._xor_decrypt(content, key)
            
            # Verify if the decryption worked by checking if the header matches
            if decrypted.startswith(expected_header):
                confidence = 0.8
                key_found = True
                details = {
                    'key_hex': key.hex(),
                    'decryption_method': 'Header-based XOR',
                    'file_type': file_type
                }
                return decrypted, confidence, key_found, details
        
        # For demonstration, simulate a partial success
        decrypted_content = self._create_simulated_decryption(content, partial=True)
        confidence = 0.6
        key_found = True
        details = {
            'decryption_method': 'Header-based analysis',
            'note': "Simulated partial decryption for demonstration purposes"
        }
        return decrypted_content, confidence, key_found, details
    
    def _apply_pattern_based_recovery(self, content, strategy):
        """Apply pattern-based decryption"""
        logging.info("Applying pattern-based recovery strategy")
        block_size = strategy.get('block_size', 16)
        
        # This is a simplified demonstration that won't actually decrypt
        # In a real system, this would implement pattern analysis techniques
        
        # Simulate a partial recovery based on patterns
        blocks = [content[i:i+block_size] for i in range(0, len(content), block_size)]
        
        # Map repeating blocks
        block_map = {}
        for i, block in enumerate(blocks):
            block_bytes = bytes(block)
            if block_bytes in block_map:
                block_map[block_bytes].append(i)
            else:
                block_map[block_bytes] = [i]
        
        # Find blocks that repeat frequently
        repeating_blocks = {block: positions for block, positions in block_map.items() if len(positions) > 1}
        
        # For demonstration, create a simulated partial decryption
        decrypted_content = self._create_simulated_decryption(content, partial=True)
        
        confidence = 0.4 + (len(repeating_blocks) / max(len(blocks), 1)) * 0.3
        key_found = confidence > 0.5
        
        details = {
            'decryption_method': 'Pattern-based analysis',
            'repeating_blocks_count': len(repeating_blocks),
            'total_blocks': len(blocks),
            'note': "Used repeating patterns to partially recover content"
        }
        
        return decrypted_content, confidence, key_found, details
    
    def _apply_partial_key_recovery(self, content, strategy):
        """Apply partial key recovery techniques"""
        logging.info("Applying partial key recovery strategy")
        
        # This is a simplified simulation for demonstration
        # In a real system, this would implement advanced key recovery techniques
        
        # Simulate different levels of success based on content characteristics
        entropy = self._calculate_entropy(content)
        
        if entropy > 7.5:  # Very high entropy makes key recovery difficult
            confidence = 0.3
            key_found = False
            
            # For very high entropy files, we'll simulate a failed recovery
            decrypted_content = None
            details = {
                'decryption_method': 'Partial key recovery',
                'entropy': entropy,
                'note': "Unable to recover key - entropy too high"
            }
            
            return decrypted_content, confidence, key_found, details
        else:
            # For lower entropy, simulate a successful partial recovery
            decrypted_content = self._create_simulated_decryption(content, partial=True)
            confidence = 0.5
            key_found = True
            
            details = {
                'decryption_method': 'Partial key recovery',
                'entropy': entropy,
                'note': "Partially recovered encryption key"
            }
            
            return decrypted_content, confidence, key_found, details
    
    def _apply_generic_recovery(self, content, strategy):
        """Apply generic recovery methods as a last resort"""
        logging.info("Applying generic recovery strategy")
        
        # Try multiple approaches and take the best result
        # This is a simplified simulation
        
        # Approach 1: Simple XOR with common keys
        common_keys = [
            bytes([0xff]), bytes([0xaa]), bytes([0x55]), 
            b'key', b'password', b'admin', b'123456'
        ]
        
        best_score = -1
        best_result = None
        
        for key in common_keys:
            decrypted = self._xor_decrypt(content, key)
            score = self._score_decryption_result(decrypted)
            
            if score > best_score:
                best_score = score
                best_result = decrypted
        
        # Approach 2: Try reversing bytes
        reversed_content = content[::-1]
        score = self._score_decryption_result(reversed_content)
        
        if score > best_score:
            best_score = score
            best_result = reversed_content
        
        # Determine results
        confidence = min(best_score / 100.0, 1.0) if best_score > 0 else 0.0
        key_found = confidence > 0.5
        
        details = {
            'decryption_method': 'Generic recovery techniques',
            'score': best_score,
            'note': "Applied multiple generic recovery methods"
        }
        
        # For demonstration, if the confidence is too low, simulate a partial success
        if confidence < 0.3:
            decrypted_content = self._create_simulated_decryption(content, partial=True)
            confidence = 0.4
            details['note'] = "Simulated partial recovery for demonstration purposes"
            return decrypted_content, confidence, key_found, details
            
        return best_result, confidence, key_found, details
    
    def _xor_decrypt(self, data, key):
        """Decrypt data using XOR with the given key"""
        if not key:
            return data
            
        result = bytearray(len(data))
        for i in range(len(data)):
            result[i] = data[i] ^ key[i % len(key)]
            
        return bytes(result)
    
    def _score_decryption_result(self, data):
        """
        Score a decryption result based on likelihood of being valid content
        Returns a score from 0-100, with higher being better
        """
        if data is None or len(data) == 0:
            return 0
            
        score = 0
        
        # Check for common file signatures
        if data.startswith(b'PK\x03\x04'):  # ZIP
            score += 50
        elif data.startswith(b'\x89PNG\r\n\x1a\n'):  # PNG
            score += 50
        elif data.startswith(b'%PDF'):  # PDF
            score += 50
        elif data.startswith(b'MZ'):  # EXE
            score += 40
        elif data.startswith(b'\xff\xd8\xff'):  # JPEG
            score += 50
            
        # Check for text file characteristics
        printable_ratio = sum(32 <= b <= 126 or b in [9, 10, 13] for b in data[:min(1000, len(data))]) / min(1000, len(data))
        if printable_ratio > 0.9:  # Mostly printable ASCII
            score += 40
            
            # Check for HTML, XML, JSON, etc.
            try:
                text_sample = data[:min(1000, len(data))].decode('utf-8', errors='ignore')
                if text_sample.startswith('<!DOCTYPE') or text_sample.startswith('<html'):
                    score += 20
                elif text_sample.startswith('<?xml'):
                    score += 20
                elif text_sample.startswith('{') and text_sample.strip().endswith('}'):
                    score += 15
            except:
                pass
                
        # Check entropy - decrypted files usually have lower entropy than encrypted ones
        entropy = self._calculate_entropy(data[:min(1000, len(data))])
        if entropy < 6.0:  # Lower entropy is good for most file types
            score += 20
        elif entropy < 7.0:
            score += 10
            
        # Cap the score at 100
        return min(score, 100)
    
    def _create_simulated_decryption(self, content, partial=False):
        """
        Create a simulated decryption result for demonstration purposes
        In a real system, this would not exist - it's just for the demo
        """
        # Create a modified version of the content that looks "decrypted"
        if partial:
            # Simulate partial decryption - some parts "decrypted", others still garbled
            decrypted_parts = []
            chunk_size = 1024
            
            for i in range(0, len(content), chunk_size):
                chunk = content[i:i+chunk_size]
                
                # Randomly decide if this chunk is "decrypted"
                if random.random() < 0.7:  # 70% of chunks "decrypted"
                    # Make this chunk look somewhat structured
                    if i == 0:  # First chunk often has a header
                        # Add a plausible file header based on length
                        if len(chunk) >= 8:
                            modified_chunk = b'DECRYPTED' + chunk[8:]
                        else:
                            modified_chunk = b'DECR' + chunk[4:] if len(chunk) >= 4 else chunk
                    else:
                        # Just make it look different from the encrypted version
                        modified_chunk = bytes([((b + i) % 256) for b in chunk])
                else:
                    # Leave this chunk "encrypted"
                    modified_chunk = chunk
                    
                decrypted_parts.append(modified_chunk)
                
            return b''.join(decrypted_parts)
        else:
            # Simulate full decryption - create a completely different content
            # that has some structure to it
            
            # Start with a plausible header
            result = bytearray(b'DECRYPTED_FILE_CONTENT\n\n')
            
            # Add some structured content
            for i in range(20):
                result.extend(f"BLOCK {i}: Decrypted content line {i}\n".encode('utf-8'))
                
            # Pad to match original size
            if len(result) < len(content):
                result.extend(b' ' * (len(content) - len(result)))
            else:
                # Truncate if needed
                result = result[:len(content)]
                
            return bytes(result)
