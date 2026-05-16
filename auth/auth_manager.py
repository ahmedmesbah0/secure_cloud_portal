"""
Authentication Manager - User registration, login, and session management.

Uses salted SHA-256 hashing for password storage (no plaintext passwords).
Sessions are managed with random tokens and expiry times.
User data and file metadata are stored in a SQLite database.
"""

import hashlib
import os
import sqlite3
import time


class AuthManager:
    """
    Manages user authentication with salted password hashing.
    User credentials and file metadata are persisted in a SQLite database.

    Usage:
        auth = AuthManager('data/portal.db')
        auth.register('alice', 'password123')
        token = auth.login('alice', 'password123')
        user = auth.validate_session(token)
    """

    SESSION_DURATION = 3600  # 1 hour

    def __init__(self, db_path: str = 'data/portal.db'):
        """Initialize and connect to the SQLite database."""
        self.db_path = db_path
        self.sessions = {}  # token -> {username, expires_at}

        # Ensure data directory exists
        os.makedirs(os.path.dirname(db_path), exist_ok=True)

        # Connect and create tables
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._create_tables()

    def _create_tables(self):
        """Create the users and files tables if they don't exist."""
        cursor = self.conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                salt TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                created_at REAL NOT NULL
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                owner TEXT NOT NULL,
                filename TEXT NOT NULL,
                file_path TEXT NOT NULL,
                file_size INTEGER DEFAULT 0,
                uploaded_at REAL NOT NULL,
                FOREIGN KEY (owner) REFERENCES users(username),
                UNIQUE(owner, filename)
            )
        ''')
        self.conn.commit()

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
        4. Store username, salt, and hash in the database
        """
        cursor = self.conn.cursor()
        cursor.execute('SELECT 1 FROM users WHERE username = ?', (username,))
        if cursor.fetchone():
            print(f"[AUTH] User '{username}' already exists")
            return False

        salt = self._generate_salt()
        password_hash = self._hash_password(password, salt)

        cursor.execute(
            'INSERT INTO users (username, salt, password_hash, created_at) VALUES (?, ?, ?, ?)',
            (username, salt, password_hash, time.time())
        )
        self.conn.commit()
        print(f"[AUTH] User '{username}' registered successfully")
        return True

    def login(self, username: str, password: str) -> str:
        """
        Authenticate user and create a session.

        Returns session token on success, None on failure.
        """
        cursor = self.conn.cursor()
        cursor.execute(
            'SELECT salt, password_hash FROM users WHERE username = ?',
            (username,)
        )
        row = cursor.fetchone()

        if not row:
            print(f"[AUTH] Login failed: user '{username}' not found")
            return None

        password_hash = self._hash_password(password, row['salt'])

        if password_hash != row['password_hash']:
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
        cursor = self.conn.cursor()
        cursor.execute('SELECT 1 FROM users WHERE username = ?', (username,))
        return cursor.fetchone() is not None

    def list_users(self) -> list:
        """List all registered usernames."""
        cursor = self.conn.cursor()
        cursor.execute('SELECT username FROM users')
        return [row['username'] for row in cursor.fetchall()]

    # ────────────────────────────────────────
    #  File metadata tracking
    # ────────────────────────────────────────

    def record_file(self, owner: str, filename: str,
                    file_path: str, file_size: int):
        """Record a file upload in the database."""
        cursor = self.conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO files (owner, filename, file_path, file_size, uploaded_at)
            VALUES (?, ?, ?, ?, ?)
        ''', (owner, filename, file_path, file_size, time.time()))
        self.conn.commit()
        print(f"[DB] Recorded file '{filename}' for user '{owner}'")

    def get_user_files(self, owner: str) -> list:
        """Retrieve all file records for a user from the database."""
        cursor = self.conn.cursor()
        cursor.execute(
            'SELECT filename, file_path, file_size, uploaded_at FROM files WHERE owner = ?',
            (owner,)
        )
        return [dict(row) for row in cursor.fetchall()]

    def delete_file_record(self, owner: str, filename: str) -> bool:
        """Delete a file record from the database."""
        cursor = self.conn.cursor()
        cursor.execute(
            'DELETE FROM files WHERE owner = ? AND filename = ?',
            (owner, filename)
        )
        self.conn.commit()
        return cursor.rowcount > 0

    def get_all_data(self) -> dict:
        """
        Retrieve all users and their files from the database.
        Useful for inspection / debugging.
        """
        cursor = self.conn.cursor()

        cursor.execute('SELECT username, created_at FROM users')
        users = [dict(row) for row in cursor.fetchall()]

        cursor.execute('SELECT owner, filename, file_path, file_size, uploaded_at FROM files')
        files = [dict(row) for row in cursor.fetchall()]

        return {'users': users, 'files': files}

    def close(self):
        """Close the database connection."""
        if self.conn:
            self.conn.close()
