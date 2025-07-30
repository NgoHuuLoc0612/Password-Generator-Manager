"""
Configuration Module
Handles application settings and configuration
"""

import json
import os
from typing import Dict, Any, Optional
from dataclasses import dataclass, asdict

@dataclass
class PasswordConfig:
    """Password generation configuration"""
    default_length: int = 16
    min_length: int = 8
    max_length: int = 128
    include_uppercase: bool = True
    include_lowercase: bool = True
    include_digits: bool = True
    include_symbols: bool = True
    exclude_ambiguous: bool = False
    custom_symbols: str = "!@#$%^&*()_+-=[]{}|;:,.<>?"

@dataclass
class PassphraseConfig:
    """Passphrase generation configuration"""
    default_word_count: int = 4
    min_word_count: int = 2
    max_word_count: int = 10
    default_separator: str = "-"
    capitalize_words: bool = True
    add_numbers: bool = False
    add_symbols: bool = False

@dataclass
class SecurityConfig:
    """Security configuration"""
    pbkdf2_iterations: int = 100000
    key_derivation_method: str = "pbkdf2"  # or "scrypt"
    salt_length: int = 32
    backup_on_change: bool = True
    auto_lock_timeout: int = 300  # seconds
    max_failed_attempts: int = 3
    require_master_password_change: int = 0  # days (0 = never)

@dataclass
class UIConfig:
    """User interface configuration"""
    clear_screen_on_start: bool = True
    show_banner: bool = True
    copy_to_clipboard_on_generate: bool = True
    show_password_strength: bool = True
    color_output: bool = True
    page_size: int = 10  # for listing entries

@dataclass
class FileConfig:
    """File paths and names configuration"""
    vault_file: str = "passwords.vault"
    config_file: str = "config.json"
    log_file: str = "password_manager.log"
    wordlist_file: str = "wordlist.txt"
    backup_directory: str = "backups"
    export_directory: str = "exports"

@dataclass
class AppConfig:
    """Main application configuration"""
    password: PasswordConfig
    passphrase: PassphraseConfig
    security: SecurityConfig
    ui: UIConfig
    files: FileConfig
    
    def __init__(self):
        self.password = PasswordConfig()
        self.passphrase = PassphraseConfig()
        self.security = SecurityConfig()
        self.ui = UIConfig()
        self.files = FileConfig()

class ConfigManager:
    """Manage application configuration"""
    
    def __init__(self, config_file: str = "config.json"):
        """
        Initialize configuration manager
        
        Args:
            config_file: Path to configuration file
        """
        self.config_file = config_file
        self.config = AppConfig()
        self.load_config()
    
    def load_config(self) -> None:
        """Load configuration from file"""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    self._update_config_from_dict(data)
                print(f"Configuration loaded from {self.config_file}")
            else:
                print("No configuration file found, using defaults")
                self.save_config()  # Create default config file
        except Exception as e:
            print(f"Error loading configuration: {e}")
            print("Using default configuration")
    
    def save_config(self) -> bool:
        """
        Save current configuration to file
        
        Returns:
            True if successful
        """
        try:
            config_dict = {
                'password': asdict(self.config.password),
                'passphrase': asdict(self.config.passphrase),
                'security': asdict(self.config.security),
                'ui': asdict(self.config.ui),
                'files': asdict(self.config.files)
            }
            
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(config_dict, f, indent=2)
            
            return True
            
        except Exception as e:
            print(f"Error saving configuration: {e}")
            return False
    
    def _update_config_from_dict(self, data: Dict[str, Any]) -> None:
        """Update configuration from dictionary"""
        if 'password' in data:
            self._update_dataclass(self.config.password, data['password'])
        
        if 'passphrase' in data:
            self._update_dataclass(self.config.passphrase, data['passphrase'])
        
        if 'security' in data:
            self._update_dataclass(self.config.security, data['security'])
        
        if 'ui' in data:
            self._update_dataclass(self.config.ui, data['ui'])
        
        if 'files' in data:
            self._update_dataclass(self.config.files, data['files'])
    
    def _update_dataclass(self, obj: object, data: Dict[str, Any]) -> None:
        """Update dataclass object with dictionary data"""
        for key, value in data.items():
            if hasattr(obj, key):
                setattr(obj, key, value)
    
    def reset_to_defaults(self) -> None:
        """Reset configuration to default values"""
        self.config = AppConfig()
        self.save_config()
    
    def get_password_config(self) -> PasswordConfig:
        """Get password configuration"""
        return self.config.password
    
    def get_passphrase_config(self) -> PassphraseConfig:
        """Get passphrase configuration"""
        return self.config.passphrase
    
    def get_security_config(self) -> SecurityConfig:
        """Get security configuration"""
        return self.config.security
    
    def get_ui_config(self) -> UIConfig:
        """Get UI configuration"""
        return self.config.ui
    
    def get_files_config(self) -> FileConfig:
        """Get files configuration"""
        return self.config.files
    
    def update_password_config(self, **kwargs) -> None:
        """
        Update password configuration
        
        Args:
            **kwargs: Configuration parameters to update
        """
        for key, value in kwargs.items():
            if hasattr(self.config.password, key):
                setattr(self.config.password, key, value)
        self.save_config()
    
    def update_passphrase_config(self, **kwargs) -> None:
        """
        Update passphrase configuration
        
        Args:
            **kwargs: Configuration parameters to update
        """
        for key, value in kwargs.items():
            if hasattr(self.config.passphrase, key):
                setattr(self.config.passphrase, key, value)
        self.save_config()
    
    def update_security_config(self, **kwargs) -> None:
        """
        Update security configuration
        
        Args:
            **kwargs: Configuration parameters to update
        """
        for key, value in kwargs.items():
            if hasattr(self.config.security, key):
                setattr(self.config.security, key, value)
        self.save_config()
    
    def update_ui_config(self, **kwargs) -> None:
        """
        Update UI configuration
        
        Args:
            **kwargs: Configuration parameters to update
        """
        for key, value in kwargs.items():
            if hasattr(self.config.ui, key):
                setattr(self.config.ui, key, value)
        self.save_config()
    
    def update_files_config(self, **kwargs) -> None:
        """
        Update files configuration
        
        Args:
            **kwargs: Configuration parameters to update
        """
        for key, value in kwargs.items():
            if hasattr(self.config.files, key):
                setattr(self.config.files, key, value)
        self.save_config()
    
    def validate_config(self) -> Dict[str, list]:
        """
        Validate current configuration
        
        Returns:
            Dictionary with validation errors by section
        """
        errors = {
            'password': [],
            'passphrase': [],
            'security': [],
            'ui': [],
            'files': []
        }
        
        # Validate password config
        if not (8 <= self.config.password.default_length <= 128):
            errors['password'].append("Default password length must be between 8 and 128")
        
        if not (8 <= self.config.password.min_length <= self.config.password.max_length <= 128):
            errors['password'].append("Invalid password length limits")
        
        # Validate passphrase config
        if not (2 <= self.config.passphrase.default_word_count <= 10):
            errors['passphrase'].append("Default word count must be between 2 and 10")
        
        if not (2 <= self.config.passphrase.min_word_count <= self.config.passphrase.max_word_count <= 10):
            errors['passphrase'].append("Invalid word count limits")
        
        # Validate security config
        if self.config.security.pbkdf2_iterations < 10000:
            errors['security'].append("PBKDF2 iterations should be at least 10,000")
        
        if self.config.security.salt_length < 16:
            errors['security'].append("Salt length should be at least 16 bytes")
        
        if self.config.security.key_derivation_method not in ['pbkdf2', 'scrypt']:
            errors['security'].append("Key derivation method must be 'pbkdf2' or 'scrypt'")
        
        # Validate UI config
        if self.config.ui.page_size < 1:
            errors['ui'].append("Page size must be at least 1")
        
        # Remove empty error lists
        return {k: v for k, v in errors.items() if v}
    
    def export_config(self, filename: str) -> bool:
        """
        Export configuration to file
        
        Args:
            filename: Export filename
            
        Returns:
            True if successful
        """
        try:
            config_dict = {
                'password': asdict(self.config.password),
                'passphrase': asdict(self.config.passphrase),
                'security': asdict(self.config.security),
                'ui': asdict(self.config.ui),
                'files': asdict(self.config.files),
                'exported_at': datetime.now().isoformat(),
                'version': '1.0'
            }
            
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(config_dict, f, indent=2)
            
            return True
            
        except Exception as e:
            print(f"Error exporting configuration: {e}")
            return False
    
    def import_config(self, filename: str) -> bool:
        """
        Import configuration from file
        
        Args:
            filename: Import filename
            
        Returns:
            True if successful
        """
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Remove metadata fields
            data.pop('exported_at', None)
            data.pop('version', None)
            
            self._update_config_from_dict(data)
            self.save_config()
            
            return True
            
        except Exception as e:
            print(f"Error importing configuration: {e}")
            return False
    
    def get_config_summary(self) -> str:
        """
        Get human-readable configuration summary
        
        Returns:
            Configuration summary string
        """
        summary = []
        
        summary.append("=== PASSWORD CONFIGURATION ===")
        summary.append(f"Default Length: {self.config.password.default_length}")
        summary.append(f"Length Range: {self.config.password.min_length}-{self.config.password.max_length}")
        summary.append(f"Include Uppercase: {self.config.password.include_uppercase}")
        summary.append(f"Include Lowercase: {self.config.password.include_lowercase}")
        summary.append(f"Include Digits: {self.config.password.include_digits}")
        summary.append(f"Include Symbols: {self.config.password.include_symbols}")
        summary.append(f"Exclude Ambiguous: {self.config.password.exclude_ambiguous}")
        
        summary.append("\n=== PASSPHRASE CONFIGURATION ===")
        summary.append(f"Default Word Count: {self.config.passphrase.default_word_count}")
        summary.append(f"Word Count Range: {self.config.passphrase.min_word_count}-{self.config.passphrase.max_word_count}")
        summary.append(f"Default Separator: '{self.config.passphrase.default_separator}'")
        summary.append(f"Capitalize Words: {self.config.passphrase.capitalize_words}")
        
        summary.append("\n=== SECURITY CONFIGURATION ===")
        summary.append(f"PBKDF2 Iterations: {self.config.security.pbkdf2_iterations:,}")
        summary.append(f"Key Derivation: {self.config.security.key_derivation_method.upper()}")
        summary.append(f"Salt Length: {self.config.security.salt_length} bytes")
        summary.append(f"Auto Backup: {self.config.security.backup_on_change}")
        summary.append(f"Auto Lock: {self.config.security.auto_lock_timeout}s")
        
        summary.append("\n=== UI CONFIGURATION ===")
        summary.append(f"Clear Screen: {self.config.ui.clear_screen_on_start}")
        summary.append(f"Show Banner: {self.config.ui.show_banner}")
        summary.append(f"Auto Copy: {self.config.ui.copy_to_clipboard_on_generate}")
        summary.append(f"Show Strength: {self.config.ui.show_password_strength}")
        summary.append(f"Page Size: {self.config.ui.page_size}")
        
        summary.append("\n=== FILE CONFIGURATION ===")
        summary.append(f"Vault File: {self.config.files.vault_file}")
        summary.append(f"Wordlist File: {self.config.files.wordlist_file}")
        summary.append(f"Backup Directory: {self.config.files.backup_directory}")
        summary.append(f"Export Directory: {self.config.files.export_directory}")
        
        return "\n".join(summary)