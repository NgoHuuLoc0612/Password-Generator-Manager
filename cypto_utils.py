"""
Cryptographic Utilities Module
Additional security functions for the password manager
"""

import hashlib
import hmac
import secrets
import base64
from typing import Tuple, Optional
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend

class CryptoUtils:
    """Cryptographic utility functions"""
    
    @staticmethod
    def generate_salt(length: int = 32) -> bytes:
        """
        Generate cryptographically secure random salt
        
        Args:
            length: Salt length in bytes
            
        Returns:
            Random salt bytes
        """
        return secrets.token_bytes(length)
    
    @staticmethod
    def derive_key_pbkdf2(
        password: str, 
        salt: bytes, 
        iterations: int = 100000,
        key_length: int = 32
    ) -> bytes:
        """
        Derive key using PBKDF2
        
        Args:
            password: Password string
            salt: Salt bytes
            iterations: Number of iterations
            key_length: Desired key length
            
        Returns:
            Derived key bytes
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=key_length,
            salt=salt,
            iterations=iterations,
            backend=default_backend()
        )
        return kdf.derive(password.encode('utf-8'))
    
    @staticmethod
    def derive_key_scrypt(
        password: str,
        salt: bytes,
        n: int = 2**14,
        r: int = 8,
        p: int = 1,
        key_length: int = 32
    ) -> bytes:
        """
        Derive key using Scrypt (more secure but slower)
        
        Args:
            password: Password string
            salt: Salt bytes
            n: CPU/memory cost parameter
            r: Block size parameter
            p: Parallelization parameter
            key_length: Desired key length
            
        Returns:
            Derived key bytes
        """
        kdf = Scrypt(
            algorithm=hashes.SHA256(),
            length=key_length,
            salt=salt,
            n=n,
            r=r,
            p=p,
            backend=default_backend()
        )
        return kdf.derive(password.encode('utf-8'))
    
    @staticmethod
    def secure_hash(data: str, salt: bytes) -> str:
        """
        Create secure hash of data with salt
        
        Args:
            data: Data to hash
            salt: Salt bytes
            
        Returns:
            Hex-encoded hash string
        """
        return hashlib.pbkdf2_hmac('sha256', data.encode(), salt, 100000).hex()
    
    @staticmethod
    def verify_hash(data: str, salt: bytes, hash_value: str) -> bool:
        """
        Verify data against hash
        
        Args:
            data: Data to verify
            salt: Salt bytes
            hash_value: Expected hash value
            
        Returns:
            True if hash matches
        """
        return hmac.compare_digest(
            CryptoUtils.secure_hash(data, salt),
            hash_value
        )
    
    @staticmethod
    def generate_fernet_key() -> bytes:
        """
        Generate a Fernet-compatible key
        
        Returns:
            Base64-encoded Fernet key
        """
        return Fernet.generate_key()
    
    @staticmethod
    def encrypt_data(data: str, key: bytes) -> bytes:
        """
        Encrypt data using Fernet
        
        Args:
            data: Data to encrypt
            key: Encryption key
            
        Returns:
            Encrypted data bytes
        """
        f = Fernet(key)
        return f.encrypt(data.encode('utf-8'))
    
    @staticmethod
    def decrypt_data(encrypted_data: bytes, key: bytes) -> str:
        """
        Decrypt data using Fernet
        
        Args:
            encrypted_data: Encrypted data bytes
            key: Decryption key
            
        Returns:
            Decrypted data string
        """
        f = Fernet(key)
        return f.decrypt(encrypted_data).decode('utf-8')
    
    @staticmethod
    def secure_compare(a: str, b: str) -> bool:
        """
        Timing-safe string comparison
        
        Args:
            a: First string
            b: Second string
            
        Returns:
            True if strings are equal
        """
        return hmac.compare_digest(a.encode(), b.encode())
    
    @staticmethod
    def generate_session_token(length: int = 32) -> str:
        """
        Generate secure session token
        
        Args:
            length: Token length in bytes
            
        Returns:
            URL-safe base64 encoded token
        """
        return base64.urlsafe_b64encode(secrets.token_bytes(length)).decode()
    
    @staticmethod
    def calculate_entropy(password: str) -> float:
        """
        Calculate password entropy
        
        Args:
            password: Password to analyze
            
        Returns:
            Entropy in bits
        """
        import math
        
        # Character set size estimation
        charset_size = 0
        
        if any(c.islower() for c in password):
            charset_size += 26
        if any(c.isupper() for c in password):
            charset_size += 26
        if any(c.isdigit() for c in password):
            charset_size += 10
        if any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
            charset_size += 22
        
        if charset_size == 0:
            return 0
        
        # Calculate entropy: log2(charset_size^length)
        return len(password) * math.log2(charset_size)
    
    @staticmethod
    def key_stretching(
        password: str,
        salt: bytes,
        rounds: int = 10000
    ) -> Tuple[bytes, int]:
        """
        Perform key stretching to slow down brute force attacks
        
        Args:
            password: Password to stretch
            salt: Salt bytes
            rounds: Number of stretching rounds
            
        Returns:
            Tuple of (stretched_key, actual_rounds_performed)
        """
        key = password.encode()
        
        for i in range(rounds):
            key = hashlib.sha256(key + salt + str(i).encode()).digest()
        
        return key, rounds
    
    @staticmethod
    def zeroize_memory(data: bytearray) -> None:
        """
        Securely clear sensitive data from memory
        
        Args:
            data: Bytearray to clear
        """
        for i in range(len(data)):
            data[i] = 0
    
    @staticmethod
    def generate_backup_codes(count: int = 8, length: int = 8) -> list:
        """
        Generate backup recovery codes
        
        Args:
            count: Number of codes to generate
            length: Length of each code
            
        Returns:
            List of backup codes
        """
        codes = []
        for _ in range(count):
            # Generate alphanumeric code
            code = ''.join(secrets.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789') 
                          for _ in range(length))
            # Format with dashes for readability
            formatted_code = '-'.join(code[i:i+4] for i in range(0, len(code), 4))
            codes.append(formatted_code)
        
        return codes
    
    @staticmethod
    def validate_master_password_strength(password: str) -> dict:
        """
        Validate master password strength
        
        Args:
            password: Password to validate
            
        Returns:
            Dictionary with validation results
        """
        result = {
            'valid': False,
            'score': 0,
            'errors': [],
            'warnings': [],
            'entropy': CryptoUtils.calculate_entropy(password)
        }
        
        # Check minimum length
        if len(password) < 12:
            result['errors'].append("Password must be at least 12 characters long")
        else:
            result['score'] += 2
        
        # Check character variety
        has_lower = any(c.islower() for c in password)
        has_upper = any(c.isupper() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_symbol = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)
        
        char_types = sum([has_lower, has_upper, has_digit, has_symbol])
        
        if char_types < 3:
            result['errors'].append("Password must contain at least 3 different character types")
        else:
            result['score'] += char_types
        
        # Check for common patterns
        common_patterns = ['123', 'abc', 'password', 'qwerty', '000', '111']
        for pattern in common_patterns:
            if pattern.lower() in password.lower():
                result['warnings'].append(f"Contains common pattern: {pattern}")
                result['score'] -= 1
        
        # Check entropy
        if result['entropy'] < 50:
            result['warnings'].append("Password entropy is relatively low")
        elif result['entropy'] > 80:
            result['score'] += 2
        
        # Determine if valid
        result['valid'] = len(result['errors']) == 0 and result['score'] >= 5
        
        return result