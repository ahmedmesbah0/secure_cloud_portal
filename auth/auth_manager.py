"""
Authentication Manager - User registration, login, and session management.

Uses salted SHA-256 hashing for password storage (no plaintext passwords).
Sessions are managed with random tokens and expiry times.
"""

import hashlib
import json
import os
import time


class AuthManager:
    """
    Manages user authentication with salted password hashing.
    
    Usage:
        auth = AuthManager('data/users.json')
        auth.register('alice', 'password123')
        token = auth.login('alice', 'password123')
        user = auth.validate_session(token)
    """
    
    SESSION_DURATION = 3600  # 1 hour
    
    def __init__(self, db_path: str = 'data/users.json'):
        """Load or create user database."""
        self.db_path = db_path
        self.sessions = {}  # token -> {username, expires_at}
        
        # Ensure data directory exists
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        
        # Load existing users or create empty db
        if os.path.exists(db_path):
            with open(db_path, 'r') as f:
                self.users = json.load(f)
        else:
            self.users = {}
            self._save()
    
    def _save(self):
        """Save user database to disk."""
        with open(self.db_path, 'w') as f:
            json.dump(self.users, f, indent=2)
    
    @staticmethod
    def _hash_password(password: str, salt: str) -> str:
        """
        Hash password with salt using SHA-256.
        
        Process: SHA256(salt + password) -> hex string
        The salt prevents rainbow table attacks.
        """
        combined = (salt + password).encode('utf-8')
        return hashlib.sha256(combined).hexdigest()
    
    @staticmethod
    def _generate_salt() -> str:
        """Generate a random 16-byte salt as hex string."""
        return os.urandom(16).hex()
    
    @staticmethod
    def _generate_token() -> str:
        """Generate a random session token."""
        return os.urandom(32).hex()
    
    def register(self, username: str, password: str) -> bool:
        """
        Register a new user.
        
        Steps:
        1. Check if username already exists
        2. Generate random salt
        3. Hash password with salt
        4. Store username, salt, and hash
        """
        if username in self.users:
            print(f"[AUTH] User '{username}' already exists")
            return False
        
        salt = self._generate_salt()
        password_hash = self._hash_password(password, salt)
        
        self.users[username] = {
            'salt': salt,
            'password_hash': password_hash,
            'created_at': time.time(),
        }
        self._save()
        print(f"[AUTH] User '{username}' registered successfully")
        return True
    
    def login(self, username: str, password: str) -> str:
        """
        Authenticate user and create a session.
        
        Returns session token on success, None on failure.
        """
        if username not in self.users:
            print(f"[AUTH] Login failed: user '{username}' not found")
            return None
        
        user = self.users[username]
        password_hash = self._hash_password(password, user['salt'])
        
        if password_hash != user['password_hash']:
            print(f"[AUTH] Login failed: wrong password for '{username}'")
            return None
        
        # Create session
        token = self._generate_token()
        self.sessions[token] = {
            'username': username,
            'expires_at': time.time() + self.SESSION_DURATION,
        }
        print(f"[AUTH] User '{username}' logged in successfully")
        return token
    
    def validate_session(self, token: str) -> str:
        """
        Validate a session token.
        Returns username if valid, None if invalid/expired.
        """
        if token not in self.sessions:
            return None
        
        session = self.sessions[token]
        if time.time() > session['expires_at']:
            del self.sessions[token]
            return None
        
        return session['username']
    
    def logout(self, token: str):
        """Invalidate a session."""
        if token in self.sessions:
            user = self.sessions[token]['username']
            del self.sessions[token]
            print(f"[AUTH] User '{user}' logged out")
    
    def user_exists(self, username: str) -> bool:
        """Check if a user exists."""
        return username in self.users
    
    def list_users(self) -> list:
        """List all registered usernames."""
        return list(self.users.keys())
