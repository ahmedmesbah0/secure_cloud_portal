"""
Secure Cloud Server - Educational Secure Storage Server
===========================================================
PROJECT OVERVIEW
===========================================================

This server demonstrates a secure cloud storage system using:

1. TCP Socket Communication
2. ElGamal Key Exchange
3. ChaCha20 Secure Communication Channel
4. Blowfish File Encryption (Data at Rest)
5. User Authentication
6. Secure File Upload/Download
7. Encryption Key Rotation
8. Certificate Authority Verification

===========================================================
SECURITY ARCHITECTURE
===========================================================

Communication Security:
-----------------------
Client <---- ChaCha20 Encrypted Channel ----> Server

Storage Security:
-----------------
Files stored on disk are encrypted using Blowfish CBC mode.

Key Exchange:
-------------
ElGamal is used to derive a shared session key securely.

Authentication:
---------------
Users authenticate using username/password.

Certificates:
--------------
Server identity is verified using CA-issued certificates.

===========================================================
NOTE
===========================================================

This project is educational and demonstrates:
- Hybrid cryptography
- Secure communication
- Secure file storage
- Key exchange protocols
- Block vs stream ciphers
"""

import socket
import json
import os
import hashlib
import time
import threading

from crypto.blowfish import Blowfish
from crypto.chacha20 import ChaCha20
from crypto.elgamal import ElGamal

from auth.auth_manager import AuthManager
from ca.certificate_authority import CertificateAuthority


class SecureServer:
    """
    Secure Cloud Storage Server

    Responsibilities:
    -----------------
    - Accept client socket connections
    - Perform secure handshake
    - Create encrypted communication channel
    - Authenticate users
    - Store encrypted files
    - Handle uploads/downloads
    - Rotate encryption keys

    Example:
    --------
    server = SecureServer(
        host='127.0.0.1',
        port=5555,
        ca=ca_instance
    )

    server.start()
    """

    # ==========================================================
    # Storage configuration
    # ==========================================================

    STORAGE_DIR = 'data/files'

    # Blowfish key used to encrypt files on disk
    STORAGE_KEY_FILE = 'keys/storage_key.bin'

    def __init__(
        self,
        host: str = '127.0.0.1',
        port: int = 5555,
        ca: CertificateAuthority = None,
        elgamal_bits: int = 512
    ):

        self.host = host
        self.port = port

        print("=" * 60)
        print("[SERVER] Initializing Secure Cloud Server")
        print("=" * 60)

        # ======================================================
        # Generate ElGamal keypair
        # ======================================================
        # Used during handshake to derive shared secret
        # ======================================================

        print("[SERVER] Generating ElGamal keypair...")

        self.elgamal = ElGamal(bits=elgamal_bits)

        self.public_key = self.elgamal.get_public_key()

        print("[SERVER] Public key generated")

        # ======================================================
        # Certificate Authority Integration
        # ======================================================
        # Server requests certificate from CA
        # Used to prove server identity to clients
        # ======================================================

        self.ca = ca
        self.certificate = None

        if ca:
            print("[SERVER] Requesting certificate from CA...")

            self.certificate = ca.issue_certificate(
                "server",
                self.public_key
            )

            print("[SERVER] Certificate issued successfully")

        # ======================================================
        # Authentication System
        # ======================================================

        self.auth = AuthManager('data/portal.db')

        # ======================================================
        # Blowfish Storage Encryption
        # ======================================================
        # Files are encrypted BEFORE storing on disk.
        # This protects data at rest.
        # ======================================================

        os.makedirs(
            os.path.dirname(self.STORAGE_KEY_FILE),
            exist_ok=True
        )

        os.makedirs(self.STORAGE_DIR, exist_ok=True)

        self.storage_key = self._load_or_create_storage_key()

        self.blowfish = Blowfish(self.storage_key)

        # ======================================================
        # Active Sessions
        # ======================================================
        # Stores connected users and their secure channels
        # ======================================================

        self.sessions = {}

        self.running = False

        self.server_socket = None

        print("[SERVER] Initialization complete")
        print("=" * 60)

    # ==========================================================
    # STORAGE KEY MANAGEMENT
    # ==========================================================

    def _load_or_create_storage_key(self) -> bytes:
        """
        Load existing Blowfish storage key
        OR generate a new one.

        This key encrypts all files stored on disk.
        """

        # Load existing key
        if os.path.exists(self.STORAGE_KEY_FILE):

            with open(self.STORAGE_KEY_FILE, 'rb') as f:
                key = f.read()

            print("[SERVER] Existing storage key loaded")

            return key

        # Generate new random 128-bit key
        key = os.urandom(16)

        with open(self.STORAGE_KEY_FILE, 'wb') as f:
            f.write(key)

        print("[SERVER] New storage encryption key generated")

        return key

    # ==========================================================
    # SECURE MESSAGE TRANSMISSION
    # ==========================================================

    def _send_message(
        self,
        conn: socket.socket,
        data: dict,
        chacha: ChaCha20 = None
    ):
        """
        Send JSON message through socket.

        Steps:
        ------
        1. Serialize dictionary to JSON
        2. Convert JSON to bytes
        3. Encrypt using ChaCha20 (optional)
        4. Send length prefix
        5. Send encrypted payload
        """

        # Convert Python dictionary -> JSON bytes
        msg = json.dumps(data).encode('utf-8')

        # Encrypt communication channel
        if chacha:
            msg = chacha.encrypt(msg)

        # Send 4-byte message length first
        length = len(msg).to_bytes(4, 'big')

        conn.sendall(length + msg)

    def _recv_message(
        self,
        conn: socket.socket,
        chacha: ChaCha20 = None
    ) -> dict:
        """
        Receive encrypted JSON message.

        Steps:
        ------
        1. Read length prefix
        2. Read encrypted payload
        3. Decrypt payload
        4. Parse JSON
        """

        # ======================================================
        # Read message length
        # ======================================================

        length_data = b''

        while len(length_data) < 4:

            chunk = conn.recv(4 - len(length_data))

            if not chunk:
                return None

            length_data += chunk

        msg_len = int.from_bytes(length_data, 'big')

        # ======================================================
        # Read encrypted payload
        # ======================================================

        msg = b''

        while len(msg) < msg_len:

            chunk = conn.recv(
                min(4096, msg_len - len(msg))
            )

            if not chunk:
                return None

            msg += chunk

        # ======================================================
        # Decrypt secure channel
        # ======================================================

        if chacha:
            msg = chacha.decrypt(msg)

        return json.loads(msg.decode('utf-8'))

    # ==========================================================
    # SECURE HANDSHAKE
    # ==========================================================

    def _handshake(self, conn: socket.socket) -> ChaCha20:
        """
        Perform Secure Handshake

        SECURITY GOAL:
        --------------
        Establish encrypted communication channel securely.

        Protocol:
        ---------
        1. Server sends public key + certificate
        2. Client sends public key
        3. Both derive shared secret
        4. Shared secret -> session key
        5. Session key initializes ChaCha20

        Final Result:
        -------------
        Secure encrypted communication channel
        """

        print("[HANDSHAKE] Starting secure handshake")

        # ======================================================
        # Step 1: Send server public key
        # ======================================================

        server_data = {

            'public_key': {

                'p': self.public_key['p'],
                'g': self.public_key['g'],
                'y': self.public_key['y'],
            }
        }

        # Include certificate if available
        if self.certificate:

            server_data['certificate'] = {

                'serial': self.certificate['serial'],

                'subject': self.certificate['subject'],

                'public_key': {

                    'p': self.certificate['public_key']['p'],
                    'g': self.certificate['public_key']['g'],
                    'y': self.certificate['public_key']['y'],
                },

                'issued_at': self.certificate['issued_at'],

                'expires_at': self.certificate['expires_at'],

                'issuer': self.certificate['issuer'],

                'signature': {

                    'r': self.certificate['signature']['r'],
                    's': self.certificate['signature']['s'],
                },
            }

        self._send_message(conn, server_data)

        print("[HANDSHAKE] Server public key sent")

        # ======================================================
        # Step 2: Receive client public key
        # ======================================================

        client_data = self._recv_message(conn)

        if not client_data:
            return None

        client_y = client_data['public_key']['y']

        print("[HANDSHAKE] Client public key received")

        # ======================================================
        # Step 3: Derive shared secret
        # ======================================================

        shared_secret = self.elgamal.derive_shared_secret(
            client_y
        )

        print("[HANDSHAKE] Shared secret derived")

        # ======================================================
        # Step 4: Generate session key
        # ======================================================

        session_key = self.elgamal.derive_session_key(
            shared_secret,
            32
        )

        # Generate ChaCha20 nonce
        nonce = hashlib.sha256(
            str(shared_secret).encode() + b'nonce'
        ).digest()[:12]

        print("[HANDSHAKE] Session key generated")

        print("[HANDSHAKE] Secure channel established")

        # ======================================================
        # Create secure encrypted communication channel
        # ======================================================

        return ChaCha20(session_key, nonce)

    # ==========================================================
    # CLIENT CONNECTION HANDLER
    # ==========================================================

    def _handle_client(
        self,
        conn: socket.socket,
        addr: tuple
    ):
        """
        Handle connected client.

        Responsibilities:
        -----------------
        - Perform handshake
        - Authenticate user
        - Process commands
        - Send encrypted responses
        """

        print(f"[SERVER] New connection from {addr}")

        try:

            # ==================================================
            # Create encrypted communication channel
            # ==================================================

            chacha = self._handshake(conn)

            if not chacha:

                print("[SERVER] Handshake failed")

                return

            # Store session state
            session = {

                'username': None,
                'chacha': chacha
            }

            # ==================================================
            # Main Request Loop
            # ==================================================

            while True:

                request = self._recv_message(conn, chacha)

                if not request:
                    break

                cmd = request.get('command')

                print(f"[SERVER] Command received: {cmd}")

                response = {

                    'status': 'error',
                    'message': 'Unknown command'
                }

                # ==================================================
                # USER REGISTRATION
                # ==================================================

                if cmd == 'register':

                    ok = self.auth.register(
                        request['username'],
                        request['password']
                    )

                    response = {

                        'status': 'ok' if ok else 'error',

                        'message':
                            'Registered successfully'
                            if ok else
                            'User already exists'
                    }

                # ==================================================
                # USER LOGIN
                # ==================================================

                elif cmd == 'login':

                    token = self.auth.login(
                        request['username'],
                        request['password']
                    )

                    if token:

                        session['username'] = request['username']

                        session['token'] = token

                        response = {

                            'status': 'ok',
                            'token': token
                        }

                        print(
                            f"[AUTH] User logged in: "
                            f"{session['username']}"
                        )

                    else:

                        response = {

                            'status': 'error',

                            'message': 'Invalid credentials'
                        }

                # ==================================================
                # FILE UPLOAD
                # ==================================================

                elif cmd == 'upload':

                    if not session.get('username'):

                        response = {

                            'status': 'error',
                            'message': 'Authentication required'
                        }

                    else:

                        filename = request['filename']

                        file_data = bytes(request['data'])

                        saved = self._store_file(
                            session['username'],
                            filename,
                            file_data
                        )

                        response = {

                            'status':
                                'ok' if saved else 'error',

                            'message':
                                'File uploaded successfully'
                                if saved else
                                'Upload failed'
                        }

                # ==================================================
                # FILE DOWNLOAD
                # ==================================================

                elif cmd == 'download':

                    if not session.get('username'):

                        response = {

                            'status': 'error',
                            'message': 'Authentication required'
                        }

                    else:

                        file_data = self._retrieve_file(
                            session['username'],
                            request['filename']
                        )

                        if file_data is not None:

                            response = {

                                'status': 'ok',

                                'data': list(file_data)
                            }

                        else:

                            response = {

                                'status': 'error',

                                'message': 'File not found'
                            }

                # ==================================================
                # LIST USER FILES
                # ==================================================

                elif cmd == 'list_files':

                    if not session.get('username'):

                        response = {

                            'status': 'error',
                            'message': 'Authentication required'
                        }

                    else:

                        files = self._list_files(
                            session['username']
                        )

                        response = {

                            'status': 'ok',
                            'files': files
                        }

                # ==================================================
                # STORAGE KEY ROTATION
                # ==================================================

                elif cmd == 'rotate_key':

                    if not session.get('username'):

                        response = {

                            'status': 'error',
                            'message': 'Authentication required'
                        }

                    else:

                        self._rotate_storage_key(
                            session['username']
                        )

                        response = {

                            'status': 'ok',
                            'message': 'Encryption key rotated'
                        }

                # ==================================================
                # CLIENT DISCONNECT
                # ==================================================

                elif cmd == 'quit':

                    response = {

                        'status': 'ok',
                        'message': 'Goodbye'
                    }

                    self._send_message(
                        conn,
                        response,
                        chacha
                    )

                    break

                # ==================================================
                # Send encrypted response
                # ==================================================

                self._send_message(
                    conn,
                    response,
                    chacha
                )

        except Exception as e:

            print(f"[SERVER ERROR] {e}")

        finally:

            conn.close()

            print(f"[SERVER] Connection closed: {addr}")

    # ==========================================================
    # FILE STORAGE
    # ==========================================================

    def _store_file(
        self,
        username: str,
        filename: str,
        data: bytes
    ) -> bool:
        """
        Encrypt and store file securely.

        SECURITY:
        ---------
        Files are encrypted using Blowfish CBC mode BEFORE storage.
        """

        user_dir = os.path.join(
            self.STORAGE_DIR,
            username
        )

        os.makedirs(user_dir, exist_ok=True)

        filepath = os.path.join(
            user_dir,
            filename + '.enc'
        )

        # Generate random IV
        iv = os.urandom(8)

        # Encrypt file
        ciphertext = self.blowfish.encrypt_cbc(data, iv)

        # Save IV + ciphertext
        with open(filepath, 'wb') as f:
            f.write(iv + ciphertext)

        # Store metadata in database
        self.auth.record_file(
            username,
            filename,
            filepath,
            len(data)
        )

        print(
            f"[STORAGE] Encrypted file stored: "
            f"{filename}"
        )

        return True

    def _retrieve_file(
        self,
        username: str,
        filename: str
    ) -> bytes:
        """
        Retrieve and decrypt stored file.
        """

        filepath = os.path.join(
            self.STORAGE_DIR,
            username,
            filename + '.enc'
        )

        if not os.path.exists(filepath):
            return None

        with open(filepath, 'rb') as f:
            data = f.read()

        iv = data[:8]

        ciphertext = data[8:]

        # Decrypt file
        plaintext = self.blowfish.decrypt_cbc(
            ciphertext,
            iv
        )

        print(
            f"[STORAGE] File decrypted: "
            f"{filename}"
        )

        return plaintext

    # ==========================================================
    # FILE LISTING
    # ==========================================================

    def _list_files(self, username: str) -> list:
        """
        Return list of user files.
        """

        db_files = self.auth.get_user_files(username)

        if db_files:
            return [f['filename'] for f in db_files]

        return []

    # ==========================================================
    # KEY ROTATION
    # ==========================================================

    def _rotate_storage_key(self, username: str):
        """
        Rotate Blowfish storage encryption key.

        PROCESS:
        --------
        1. Decrypt existing files using old key
        2. Generate new encryption key
        3. Re-encrypt files using new key
        4. Save new key
        """

        user_dir = os.path.join(
            self.STORAGE_DIR,
            username
        )

        if not os.path.exists(user_dir):
            return

        old_blowfish = self.blowfish

        # Generate new Blowfish key
        new_key = os.urandom(16)

        new_blowfish = Blowfish(new_key)

        # Re-encrypt all files
        for fname in os.listdir(user_dir):

            if not fname.endswith('.enc'):
                continue

            filepath = os.path.join(user_dir, fname)

            with open(filepath, 'rb') as f:
                data = f.read()

            # Decrypt using old key
            iv_old = data[:8]

            plaintext = old_blowfish.decrypt_cbc(
                data[8:],
                iv_old
            )

            # Encrypt using new key
            iv_new = os.urandom(8)

            ciphertext = new_blowfish.encrypt_cbc(
                plaintext,
                iv_new
            )

            with open(filepath, 'wb') as f:
                f.write(iv_new + ciphertext)

        # Replace old key
        self.storage_key = new_key

        self.blowfish = new_blowfish

        with open(self.STORAGE_KEY_FILE, 'wb') as f:
            f.write(new_key)

        print("[SECURITY] Storage key rotated successfully")

    # ==========================================================
    # SERVER STARTUP
    # ==========================================================

    def start(self):
        """
        Start TCP socket server.
        """

        self.server_socket = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        )

        # Allow quick restart
        self.server_socket.setsockopt(
            socket.SOL_SOCKET,
            socket.SO_REUSEADDR,
            1
        )

        self.server_socket.bind(
            (self.host, self.port)
        )

        self.server_socket.listen(5)

        self.running = True

        print("=" * 60)
        print(
            f"[SERVER] Listening on "
            f"{self.host}:{self.port}"
        )
        print("=" * 60)

        try:

            while self.running:

                self.server_socket.settimeout(1.0)

                try:

                    conn, addr = self.server_socket.accept()

                    print(
                        f"[SERVER] Accepted connection "
                        f"from {addr}"
                    )

                    # Handle each client in separate thread
                    t = threading.Thread(

                        target=self._handle_client,

                        args=(conn, addr),

                        daemon=True
                    )

                    t.start()

                except socket.timeout:
                    continue

        except KeyboardInterrupt:

            print("\n[SERVER] Shutdown requested")

        finally:

            self.stop()

    # ==========================================================
    # SERVER SHUTDOWN
    # ==========================================================

    def stop(self):
        """
        Gracefully stop server.
        """

        self.running = False

        if self.server_socket:
            self.server_socket.close()

        print("[SERVER] Server stopped")