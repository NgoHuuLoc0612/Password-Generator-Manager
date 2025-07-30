"""
Password Generator Module
Handles password and passphrase generation with various options
"""

import secrets
import string
import os
from typing import List, Optional

class PasswordGenerator:
    """Generate secure passwords and passphrases"""
    
    def __init__(self, wordlist_file: str = "wordlist.txt"):
        """
        Initialize password generator
        
        Args:
            wordlist_file: Path to wordlist file for passphrase generation
        """
        self.wordlist_file = wordlist_file
        self._wordlist = None
        self._load_wordlist()
    
    def _load_wordlist(self) -> None:
        """Load wordlist from file"""
        try:
            if os.path.exists(self.wordlist_file):
                with open(self.wordlist_file, 'r', encoding='utf-8') as f:
                    self._wordlist = [line.strip().lower() for line in f 
                                    if line.strip() and len(line.strip()) >= 3]
                print(f"Loaded {len(self._wordlist)} words from {self.wordlist_file}")
            else:
                print(f"Wordlist file {self.wordlist_file} not found. Using default words.")
                self._create_default_wordlist()
        except Exception as e:
            print(f"Error loading wordlist: {e}. Using default words.")
            self._create_default_wordlist()
    
    def _create_default_wordlist(self) -> None:
        """Create a default wordlist if file is not available"""
        self._wordlist = [
            "apple", "banana", "cherry", "dragon", "elephant", "forest", "guitar", "house",
            "island", "jungle", "kitten", "lemon", "mountain", "notebook", "ocean", "piano",
            "queen", "rabbit", "sunset", "tiger", "umbrella", "valley", "window", "xylophone",
            "yellow", "zebra", "anchor", "bridge", "castle", "diamond", "engine", "flower",
            "garden", "hammer", "iceberg", "jacket", "kitchen", "ladder", "mirror", "needle",
            "orange", "pencil", "quartz", "rocket", "silver", "table", "unicorn", "violet",
            "wizard", "oxygen", "puzzle", "crystal", "thunder", "rainbow", "journey", "freedom",
            "harmony", "mystery", "adventure", "treasure", "compass", "starlight", "melody",
            "butterfly", "lighthouse", "waterfall", "firefly", "moonbeam", "whisper", "serenity"
        ]
    
    def generate_password(
        self,
        length: int = 16,
        include_uppercase: bool = True,
        include_lowercase: bool = True,
        include_digits: bool = True,
        include_symbols: bool = True,
        exclude_ambiguous: bool = False
    ) -> str:
        """
        Generate a secure password
        
        Args:
            length: Password length (8-128)
            include_uppercase: Include uppercase letters
            include_lowercase: Include lowercase letters
            include_digits: Include digits
            include_symbols: Include symbols
            exclude_ambiguous: Exclude ambiguous characters (0, O, l, 1, etc.)
            
        Returns:
            Generated password string
            
        Raises:
            ValueError: If length is invalid or no character types selected
        """
        if not (8 <= length <= 128):
            raise ValueError("Password length must be between 8 and 128 characters")
        
        if not any([include_uppercase, include_lowercase, include_digits, include_symbols]):
            raise ValueError("At least one character type must be selected")
        
        # Build character set
        chars = ""
        required_chars = []
        
        if include_lowercase:
            lowercase = string.ascii_lowercase
            if exclude_ambiguous:
                lowercase = lowercase.replace('l', '').replace('o', '')
            chars += lowercase
            required_chars.append(secrets.choice(lowercase))
        
        if include_uppercase:
            uppercase = string.ascii_uppercase
            if exclude_ambiguous:
                uppercase = uppercase.replace('I', '').replace('O', '')
            chars += uppercase
            required_chars.append(secrets.choice(uppercase))
        
        if include_digits:
            digits = string.digits
            if exclude_ambiguous:
                digits = digits.replace('0', '').replace('1', '')
            chars += digits
            required_chars.append(secrets.choice(digits))
        
        if include_symbols:
            symbols = "!@#$%^&*()_+-=[]{}|;:,.<>?"
            if exclude_ambiguous:
                symbols = symbols.replace('|', '').replace('`', '')
            chars += symbols
            required_chars.append(secrets.choice(symbols))
        
        # Generate password ensuring at least one character from each selected type
        password_chars = required_chars.copy()
        remaining_length = length - len(required_chars)
        
        for _ in range(remaining_length):
            password_chars.append(secrets.choice(chars))
        
        # Shuffle the characters
        secrets.SystemRandom().shuffle(password_chars)
        
        return ''.join(password_chars)
    
    def generate_passphrase(
        self,
        word_count: int = 4,
        separator: str = "-",
        capitalize: bool = True,
        add_numbers: bool = False,
        add_symbols: bool = False
    ) -> str:
        """
        Generate a passphrase using words from wordlist
        
        Args:
            word_count: Number of words (2-10)
            separator: Character(s) to separate words
            capitalize: Capitalize first letter of each word
            add_numbers: Add random numbers
            add_symbols: Add random symbols
            
        Returns:
            Generated passphrase string
            
        Raises:
            ValueError: If word_count is invalid
        """
        if not (2 <= word_count <= 10):
            raise ValueError("Word count must be between 2 and 10")
        
        if not self._wordlist:
            raise ValueError("No wordlist available")
        
        # Select random words
        words = []
        for _ in range(word_count):
            word = secrets.choice(self._wordlist)
            if capitalize:
                word = word.capitalize()
            words.append(word)
        
        # Join words with separator
        passphrase = separator.join(words)
        
        # Add numbers if requested
        if add_numbers:
            numbers = ''.join(secrets.choice(string.digits) for _ in range(2))
            passphrase += separator + numbers
        
        # Add symbols if requested
        if add_symbols:
            symbols = ''.join(secrets.choice("!@#$%^&*") for _ in range(1, 3))
            passphrase += separator + symbols
        
        return passphrase
    
    def generate_memorable_password(
        self,
        base_word: Optional[str] = None,
        length: int = 12,
        add_numbers: bool = True,
        add_symbols: bool = True
    ) -> str:
        """
        Generate a memorable password based on a word
        
        Args:
            base_word: Base word to use (random if None)
            length: Target password length
            add_numbers: Add numbers
            add_symbols: Add symbols
            
        Returns:
            Generated memorable password
        """
        if base_word is None:
            base_word = secrets.choice(self._wordlist) if self._wordlist else "password"
        
        base_word = base_word.capitalize()
        
        # Calculate remaining length for numbers and symbols
        remaining = max(0, length - len(base_word))
        
        additions = ""
        
        if add_numbers and remaining > 0:
            num_digits = min(remaining // 2, 4)
            numbers = ''.join(secrets.choice(string.digits) for _ in range(num_digits))
            additions += numbers
            remaining -= num_digits
        
        if add_symbols and remaining > 0:
            num_symbols = min(remaining, 2)
            symbols = ''.join(secrets.choice("!@#$%^&*") for _ in range(num_symbols))
            additions += symbols
        
        return base_word + additions
    
    def check_password_strength(self, password: str) -> dict:
        """
        Check password strength and return analysis
        
        Args:
            password: Password to analyze
            
        Returns:
            Dictionary with strength analysis
        """
        analysis = {
            'length': len(password),
            'has_uppercase': any(c.isupper() for c in password),
            'has_lowercase': any(c.islower() for c in password),
            'has_digits': any(c.isdigit() for c in password),
            'has_symbols': any(c in string.punctuation for c in password),
            'score': 0,
            'strength': 'Very Weak'
        }
        
        # Calculate score
        if analysis['length'] >= 8:
            analysis['score'] += 2
        if analysis['length'] >= 12:
            analysis['score'] += 1
        if analysis['length'] >= 16:
            analysis['score'] += 1
        
        if analysis['has_uppercase']:
            analysis['score'] += 1
        if analysis['has_lowercase']:
            analysis['score'] += 1
        if analysis['has_digits']:
            analysis['score'] += 1
        if analysis['has_symbols']:
            analysis['score'] += 2
        
        # Determine strength
        if analysis['score'] >= 8:
            analysis['strength'] = 'Very Strong'
        elif analysis['score'] >= 6:
            analysis['strength'] = 'Strong'
        elif analysis['score'] >= 4:
            analysis['strength'] = 'Medium'
        elif analysis['score'] >= 2:
            analysis['strength'] = 'Weak'
        
        return analysis
    
    def generate_multiple_passwords(
        self,
        count: int = 5,
        **kwargs
    ) -> List[str]:
        """
        Generate multiple passwords at once
        
        Args:
            count: Number of passwords to generate
            **kwargs: Arguments to pass to generate_password
            
        Returns:
            List of generated passwords
        """
        return [self.generate_password(**kwargs) for _ in range(count)]
    
    def generate_pattern_password(
        self,
        pattern: str = "Llllnnnn!",
        custom_chars: Optional[dict] = None
    ) -> str:
        """
        Generate password based on pattern
        
        Pattern characters:
        L = Uppercase letter
        l = Lowercase letter
        n = Number
        ! = Symbol
        ? = Any character
        
        Args:
            pattern: Pattern string
            custom_chars: Custom character sets
            
        Returns:
            Generated password following pattern
        """
        char_sets = {
            'L': string.ascii_uppercase,
            'l': string.ascii_lowercase,
            'n': string.digits,
            '!': "!@#$%^&*()_+-=[]{}|;:,.<>?",
            '?': string.ascii_letters + string.digits + "!@#$%^&*"
        }
        
        if custom_chars:
            char_sets.update(custom_chars)
        
        password = ""
        for char in pattern:
            if char in char_sets:
                password += secrets.choice(char_sets[char])
            else:
                password += char
        
        return password