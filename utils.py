"""
Utility Functions Module
Common utility functions for the password manager
"""

import os
import sys
import json
import csv
import platform
import subprocess
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
import pyperclip

def clear_screen():
    """Clear terminal screen"""
    os.system('cls' if os.name == 'nt' else 'clear')

def display_banner():
    """Display application banner"""
    banner = """
    ╔══════════════════════════════════════════════════════════════════╗
    ║                                                                  ║
    ║               PASSWORD GENERATOR & MANAGER                       ║
    ║                                                                  ║
    ║                Secure • Simple • Reliable                        ║
    ║                                                                  ║
    ╚══════════════════════════════════════════════════════════════════╝
    """
    print(banner)

def copy_to_clipboard(text: str) -> bool:
    """
    Copy text to clipboard
    
    Args:
        text: Text to copy
        
    Returns:
        True if successful
    """
    try:
        pyperclip.copy(text)
        return True
    except Exception:
        return False

def format_file_size(size_bytes: int) -> str:
    """
    Format file size in human readable format
    
    Args:
        size_bytes: Size in bytes
        
    Returns:
        Formatted size string
    """
    if size_bytes == 0:
        return "0 B"
    
    size_names = ["B", "KB", "MB", "GB", "TB"]
    import math
    i = int(math.floor(math.log(size_bytes, 1024)))
    p = math.pow(1024, i)
    s = round(size_bytes / p, 2)
    return f"{s} {size_names[i]}"

def format_datetime(dt_string: str) -> str:
    """
    Format datetime string for display
    
    Args:
        dt_string: ISO format datetime string
        
    Returns:
        Formatted datetime string
    """
    try:
        dt = datetime.fromisoformat(dt_string.replace('Z', '+00:00'))
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except:
        return dt_string

def time_ago(dt_string: str) -> str:
    """
    Get human readable time difference
    
    Args:
        dt_string: ISO format datetime string
        
    Returns:
        Time difference string
    """
    try:
        dt = datetime.fromisoformat(dt_string.replace('Z', '+00:00'))
        now = datetime.now()
        diff = now - dt
        
        if diff.days > 0:
            return f"{diff.days} days ago"
        elif diff.seconds > 3600:
            hours = diff.seconds // 3600
            return f"{hours} hours ago"
        elif diff.seconds > 60:
            minutes = diff.seconds // 60
            return f"{minutes} minutes ago"
        else:
            return "Just now"
    except:
        return "Unknown"

def validate_email(email: str) -> bool:
    """
    Basic email validation
    
    Args:
        email: Email address to validate
        
    Returns:
        True if email format is valid
    """
    import re
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validate_url(url: str) -> bool:
    """
    Basic URL validation
    
    Args:
        url: URL to validate
        
    Returns:
        True if URL format is valid
    """
    import re
    pattern = r'^https?://(?:[-\w.])+(?:\:[0-9]+)?(?:/(?:[\w/_.])*(?:\?(?:[\w&=%.])*)?(?:\#(?:[\w.])*)?)?$'
    return re.match(pattern, url) is not None

def get_system_info() -> Dict[str, str]:
    """
    Get system information
    
    Returns:
        Dictionary with system info
    """
    return {
        'platform': platform.system(),
        'platform_version': platform.version(),
        'architecture': platform.architecture()[0],
        'python_version': platform.python_version(),
        'hostname': platform.node()
    }

def secure_delete_file(filepath: str) -> bool:
    """
    Securely delete file by overwriting with random data
    
    Args:
        filepath: Path to file to delete
        
    Returns:
        True if successful
    """
    try:
        if not os.path.exists(filepath):
            return True
        
        # Get file size
        file_size = os.path.getsize(filepath)
        
        # Overwrite with random data multiple times
        with open(filepath, 'r+b') as f:
            for _ in range(3):
                f.seek(0)
                f.write(os.urandom(file_size))
                f.flush()
                os.fsync(f.fileno())
        
        # Finally delete the file
        os.remove(filepath)
        return True
        
    except Exception as e:
        print(f"Error securely deleting file: {e}")
        return False

def create_backup_filename(base_name: str) -> str:
    """
    Create timestamped backup filename
    
    Args:
        base_name: Base filename
        
    Returns:
        Backup filename with timestamp
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"{base_name}_backup_{timestamp}"

def export_to_csv(data: List[Dict[str, Any]], filename: str) -> bool:
    """
    Export data to CSV file
    
    Args:
        data: List of dictionaries to export
        filename: Output filename
        
    Returns:
        True if successful
    """
    try:
        if not data:
            return False
        
        fieldnames = data[0].keys()
        
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(data)
        
        return True
        
    except Exception as e:
        print(f"Error exporting to CSV: {e}")
        return False

def import_from_csv(filename: str) -> List[Dict[str, Any]]:
    """
    Import data from CSV file
    
    Args:
        filename: CSV filename to import
        
    Returns:
        List of dictionaries
    """
    try:
        data = []
        
        with open(filename, 'r', encoding='utf-8') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                data.append(dict(row))
        
        return data
        
    except Exception as e:
        print(f"Error importing from CSV: {e}")
        return []

def check_password_in_breaches(password: str) -> Optional[bool]:
    """
    Check if password appears in known data breaches using HaveIBeenPwned API
    Note: This sends only the first 5 characters of the SHA-1 hash
    
    Args:
        password: Password to check
        
    Returns:
        True if found in breaches, False if not found, None if error
    """
    try:
        import hashlib
        import requests
        
        # Create SHA-1 hash of password
        sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        
        # Send only first 5 characters
        prefix = sha1_hash[:5]
        suffix = sha1_hash[5:]
        
        # Query HaveIBeenPwned API
        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        response = requests.get(url, timeout=5)
        
        if response.status_code == 200:
            # Check if our suffix is in the response
            hashes = response.text.splitlines()
            for hash_line in hashes:
                hash_suffix, count = hash_line.split(':')
                if hash_suffix == suffix:
                    return True
            return False
        else:
            return None
            
    except Exception:
        return None

def generate_qr_code(data: str, filename: str) -> bool:
    """
    Generate QR code for data (useful for sharing)
    
    Args:
        data: Data to encode
        filename: Output filename
        
    Returns:
        True if successful
    """
    try:
        import qrcode
        from PIL import Image
        
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(data)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        img.save(filename)
        
        return True
        
    except Exception as e:
        print(f"Error generating QR code: {e}")
        return False

def check_internet_connection() -> bool:
    """
    Check if internet connection is available
    
    Returns:
        True if connected
    """
    try:
        import socket
        socket.create_connection(("8.8.8.8", 53), timeout=3)
        return True
    except:
        return False

def open_url_in_browser(url: str) -> bool:
    """
    Open URL in default browser
    
    Args:
        url: URL to open
        
    Returns:
        True if successful
    """
    try:
        import webbrowser
        webbrowser.open(url)
        return True
    except:
        return False

def log_activity(message: str, log_file: str = "password_manager.log") -> None:
    """
    Log activity to file
    
    Args:
        message: Message to log
        log_file: Log filename
    """
    try:
        timestamp = datetime.now().isoformat()
        log_entry = f"[{timestamp}] {message}\n"
        
        with open(log_file, 'a', encoding='utf-8') as f:
            f.write(log_entry)
            
    except Exception:
        pass  # Silently fail for logging

def confirm_action(prompt: str, default: bool = False) -> bool:
    """
    Get user confirmation for an action
    
    Args:
        prompt: Confirmation prompt
        default: Default value if user just presses Enter
        
    Returns:
        True if user confirms
    """
    suffix = " [Y/n]: " if default else " [y/N]: "
    
    while True:
        response = input(prompt + suffix).strip().lower()
        
        if not response:
            return default
        elif response in ['y', 'yes']:
            return True
        elif response in ['n', 'no']:
            return False
        else:
            print("Please enter 'y' or 'n'")

def create_directory_if_not_exists(directory: str) -> bool:
    """
    Create directory if it doesn't exist
    
    Args:
        directory: Directory path to create
        
    Returns:
        True if directory exists or was created
    """
    try:
        if not os.path.exists(directory):
            os.makedirs(directory)
        return True
    except Exception:
        return False

def get_file_hash(filepath: str, algorithm: str = 'sha256') -> Optional[str]:
    """
    Calculate file hash
    
    Args:
        filepath: Path to file
        algorithm: Hash algorithm ('md5', 'sha1', 'sha256')
        
    Returns:
        Hex-encoded hash string or None if error
    """
    try:
        import hashlib
        
        hash_obj = hashlib.new(algorithm)
        
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_obj.update(chunk)
        
        return hash_obj.hexdigest()
        
    except Exception:
        return None
