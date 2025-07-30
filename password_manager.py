"""
Password Manager Module
Handles secure storage and management of password entries
"""

import json
import os
import hashlib
import uuid
from datetime import datetime
from typing import List, Dict, Optional, Any
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

class PasswordManager:
    """Secure password manager with encryption"""
    
    def __init__(self, vault_file: str = "passwords.vault"):
        """
        Initialize password manager
        
        Args:
            vault_file: Path to encrypted vault file
        """
        self.vault_file = vault_file
        self.salt_file = vault_file + ".salt"
        self.master_hash_file = vault_file + ".hash"
        self._cipher = None
        self._entries = []
    
    def _derive_key(self, password: str, salt: bytes) -> bytes:
        """
        Derive encryption key from password using PBKDF2
        
        Args:
            password: Master password
            salt: Salt bytes
            
        Returns:
            Derived key bytes
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key
    
    def _hash_password(self, password: str, salt: bytes) -> str:
        """
        Hash password for verification
        
        Args:
            password: Password to hash
            salt: Salt bytes
            
        Returns:
            Hashed password string
        """
        return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000).hex()
    
    def has_existing_vault(self) -> bool:
        """
        Check if vault files exist
        
        Returns:
            True if vault exists
        """
        return (os.path.exists(self.vault_file) and 
                os.path.exists(self.salt_file) and 
                os.path.exists(self.master_hash_file))
    
    def initialize_vault(self, master_password: str) -> None:
        """
        Initialize new vault with master password
        
        Args:
            master_password: Master password for vault
        """
        # Generate salt
        salt = os.urandom(32)
        
        # Save salt
        with open(self.salt_file, 'wb') as f:
            f.write(salt)
        
        # Hash and save master password
        master_hash = self._hash_password(master_password, salt)
        with open(self.master_hash_file, 'w') as f:
            f.write(master_hash)
        
        # Initialize cipher
        key = self._derive_key(master_password, salt)
        self._cipher = Fernet(key)
        
        # Initialize empty vault
        self._entries = []
        self._save_vault()
    
    def authenticate(self, master_password: str) -> bool:
        """
        Authenticate with master password
        
        Args:
            master_password: Master password to verify
            
        Returns:
            True if authentication successful
        """
        try:
            # Load salt
            with open(self.salt_file, 'rb') as f:
                salt = f.read()
            
            # Load stored hash
            with open(self.master_hash_file, 'r') as f:
                stored_hash = f.read().strip()
            
            # Verify password
            password_hash = self._hash_password(master_password, salt)
            if password_hash != stored_hash:
                return False
            
            # Initialize cipher
            key = self._derive_key(master_password, salt)
            self._cipher = Fernet(key)
            
            # Load vault
            self._load_vault()
            return True
            
        except Exception as e:
            print(f"Authentication error: {e}")
            return False
    
    def _load_vault(self) -> None:
        """Load and decrypt vault data"""
        try:
            if os.path.exists(self.vault_file):
                with open(self.vault_file, 'rb') as f:
                    encrypted_data = f.read()
                
                if encrypted_data:
                    decrypted_data = self._cipher.decrypt(encrypted_data)
                    self._entries = json.loads(decrypted_data.decode())
                else:
                    self._entries = []
            else:
                self._entries = []
        except Exception as e:
            print(f"Error loading vault: {e}")
            self._entries = []
    
    def _save_vault(self) -> None:
        """Encrypt and save vault data"""
        try:
            data = json.dumps(self._entries, indent=2).encode()
            encrypted_data = self._cipher.encrypt(data)
            
            with open(self.vault_file, 'wb') as f:
                f.write(encrypted_data)
        except Exception as e:
            print(f"Error saving vault: {e}")
            raise
    
    def add_entry(
        self,
        service: str,
        username: str,
        password: str,
        url: str = "",
        notes: str = ""
    ) -> str:
        """
        Add new password entry
        
        Args:
            service: Service name
            username: Username
            password: Password
            url: Service URL (optional)
            notes: Additional notes (optional)
            
        Returns:
            Entry ID
        """
        entry_id = str(uuid.uuid4())
        entry = {
            'id': entry_id,
            'service': service,
            'username': username,
            'password': password,
            'url': url,
            'notes': notes,
            'created_at': datetime.now().isoformat(),
            'updated_at': datetime.now().isoformat()
        }
        
        self._entries.append(entry)
        self._save_vault()
        return entry_id
    
    def get_entry_by_id(self, entry_id: str) -> Optional[Dict[str, Any]]:
        """
        Get entry by ID
        
        Args:
            entry_id: Entry ID
            
        Returns:
            Entry dictionary or None if not found
        """
        for entry in self._entries:
            if entry['id'] == entry_id:
                return entry.copy()
        return None
    
    def search_entries(self, query: str) -> List[Dict[str, Any]]:
        """
        Search entries by service name or username
        
        Args:
            query: Search query
            
        Returns:
            List of matching entries
        """
        query = query.lower()
        results = []
        
        for entry in self._entries:
            if (query in entry['service'].lower() or 
                query in entry['username'].lower()):
                results.append(entry.copy())
        
        return results
    
    def list_all_entries(self) -> List[Dict[str, Any]]:
        """
        Get all entries
        
        Returns:
            List of all entries
        """
        return [entry.copy() for entry in self._entries]
    
    def update_entry(self, entry_id: str, **kwargs) -> bool:
        """
        Update existing entry
        
        Args:
            entry_id: Entry ID
            **kwargs: Fields to update
            
        Returns:
            True if entry was updated
        """
        for entry in self._entries:
            if entry['id'] == entry_id:
                # Update specified fields
                for key, value in kwargs.items():
                    if key in entry and key != 'id':
                        entry[key] = value
                
                entry['updated_at'] = datetime.now().isoformat()
                self._save_vault()
                return True
        
        return False
    
    def delete_entry(self, entry_id: str) -> bool:
        """
        Delete entry by ID
        
        Args:
            entry_id: Entry ID
            
        Returns:
            True if entry was deleted
        """
        for i, entry in enumerate(self._entries):
            if entry['id'] == entry_id:
                del self._entries[i]
                self._save_vault()
                return True
        return False
    
    def change_master_password(self, new_password: str) -> bool:
        """
        Change master password
        
        Args:
            new_password: New master password
            
        Returns:
            True if password was changed
        """
        try:
            # Generate new salt
            salt = os.urandom(32)
            
            # Save new salt
            with open(self.salt_file, 'wb') as f:
                f.write(salt)
            
            # Hash and save new master password
            master_hash = self._hash_password(new_password, salt)
            with open(self.master_hash_file, 'w') as f:
                f.write(master_hash)
            
            # Re-encrypt vault with new key
            key = self._derive_key(new_password, salt)
            self._cipher = Fernet(key)
            self._save_vault()
            
            return True
        except Exception as e:
            print(f"Error changing master password: {e}")
            return False
    
    def export_passwords(self, filename: str, include_passwords: bool = True) -> None:
        """
        Export passwords to JSON file
        
        Args:
            filename: Export filename
            include_passwords: Whether to include actual passwords
        """
        export_data = []
        
        for entry in self._entries:
            export_entry = entry.copy()
            if not include_passwords:
                export_entry['password'] = '[HIDDEN]'
            export_data.append(export_entry)
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(export_data, f, indent=2, ensure_ascii=False)
    
    def import_passwords(self, filename: str) -> int:
        """
        Import passwords from JSON file
        
        Args:
            filename: Import filename
            
        Returns:
            Number of entries imported
        """
        with open(filename, 'r', encoding='utf-8') as f:
            import_data = json.load(f)
        
        imported_count = 0
        
        for entry_data in import_data:
            # Generate new ID to avoid conflicts
            entry_id = str(uuid.uuid4())
            
            entry = {
                'id': entry_id,
                'service': entry_data.get('service', ''),
                'username': entry_data.get('username', ''),
                'password': entry_data.get('password', ''),
                'url': entry_data.get('url', ''),
                'notes': entry_data.get('notes', ''),
                'created_at': datetime.now().isoformat(),
                'updated_at': datetime.now().isoformat()
            }
            
            self._entries.append(entry)
            imported_count += 1
        
        self._save_vault()
        return imported_count
    
    def get_vault_stats(self) -> Dict[str, Any]:
        """
        Get vault statistics
        
        Returns:
            Dictionary with vault statistics
        """
        if not self._entries:
            return {
                'total_entries': 0,
                'services': [],
                'creation_dates': []
            }
        
        services = {}
        creation_dates = []
        
        for entry in self._entries:
            service = entry['service']
            if service in services:
                services[service] += 1
            else:
                services[service] = 1
            
            creation_dates.append(entry['created_at'])
        
        return {
            'total_entries': len(self._entries),
            'unique_services': len(services),
            'services': services,
            'creation_dates': sorted(creation_dates),
            'vault_size': os.path.getsize(self.vault_file) if os.path.exists(self.vault_file) else 0
        }
    
    def backup_vault(self, backup_filename: str) -> bool:
        """
        Create backup of vault files
        
        Args:
            backup_filename: Backup filename (without extension)
            
        Returns:
            True if backup was successful
        """
        try:
            import shutil
            
            # Backup main vault file
            if os.path.exists(self.vault_file):
                shutil.copy2(self.vault_file, f"{backup_filename}.vault")
            
            # Backup salt file
            if os.path.exists(self.salt_file):
                shutil.copy2(self.salt_file, f"{backup_filename}.vault.salt")
            
            # Backup hash file
            if os.path.exists(self.master_hash_file):
                shutil.copy2(self.master_hash_file, f"{backup_filename}.vault.hash")
            
            return True
        except Exception as e:
            print(f"Backup failed: {e}")
            return False
    
    def duplicate_check(self) -> List[Dict[str, Any]]:
        """
        Find duplicate entries (same service and username)
        
        Returns:
            List of duplicate entry groups
        """
        seen = {}
        duplicates = []
        
        for entry in self._entries:
            key = (entry['service'].lower(), entry['username'].lower())
            
            if key in seen:
                if len(seen[key]) == 1:
                    # First duplicate found
                    duplicates.append(seen[key])
                duplicates[-1].append(entry)
            else:
                seen[key] = [entry]
        
        return duplicates