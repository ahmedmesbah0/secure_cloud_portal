"""
Secure Cloud Server - Socket server with encryption.

Handles:
- Client connections via TCP sockets
- ElGamal key exchange (handshake) -> session key
- ChaCha20 encrypted communication channel
- Blowfish encrypted file storage (at rest)
- User authentication
- File upload/download
- Key rotation
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
    Secure cloud document server.
    
    Usage:
        server = SecureServer(host='127.0.0.1', port=5555, ca=ca_instance)
        server.start()
    """
    
    STORAGE_DIR = 'data/files'
    STORAGE_KEY_FILE = 'keys/storage_key.bin'
    
    def __init__(self, host: str = '127.0.0.1', port: int = 5555,
                 ca: CertificateAuthority = None, elgamal_bits: int = 512):
        self.host = host
        self.port = port
        
        # Generate server's ElGamal keypair
        print("[SERVER] Generating server keypair...")
        self.elgamal = ElGamal(bits=elgamal_bits)
        self.public_key = self.elgamal.get_public_key()
        
        # Get certificate from CA
        self.ca = ca
        self.certificate = None
        if ca:
            self.certificate = ca.issue_certificate("server", self.public_key)
        
        # Auth manager
        self.auth = AuthManager('data/users.json')
        
        # Storage encryption key (Blowfish)
        os.makedirs(os.path.dirname(self.STORAGE_KEY_FILE), exist_ok=True)
        os.makedirs(self.STORAGE_DIR, exist_ok=True)
        self.storage_key = self._load_or_create_storage_key()
        self.blowfish = Blowfish(self.storage_key)
        
        # Active sessions: {client_addr: {session_key, username, chacha}}
        self.sessions = {}
        self.running = False
        self.server_socket = None
    
    def _load_or_create_storage_key(self) -> bytes:
        """Load or generate the Blowfish storage key."""
        if os.path.exists(self.STORAGE_KEY_FILE):
            with open(self.STORAGE_KEY_FILE, 'rb') as f:
                return f.read()
        key = os.urandom(16)  # 128-bit Blowfish key
        with open(self.STORAGE_KEY_FILE, 'wb') as f:
            f.write(key)
        print("[SERVER] Generated new storage encryption key")
        return key
    
    def _send_message(self, conn: socket.socket, data: dict,
                      chacha: ChaCha20 = None):
        """Send a JSON message, optionally encrypted with ChaCha20."""
        msg = json.dumps(data).encode('utf-8')
        if chacha:
            msg = chacha.encrypt(msg)
        # Send length prefix (4 bytes) + message
        length = len(msg).to_bytes(4, 'big')
        conn.sendall(length + msg)
    
    def _recv_message(self, conn: socket.socket,
                      chacha: ChaCha20 = None) -> dict:
        """Receive a JSON message, optionally decrypted with ChaCha20."""
        # Read length prefix
        length_data = b''
        while len(length_data) < 4:
            chunk = conn.recv(4 - len(length_data))
            if not chunk:
                return None
            length_data += chunk
        
        msg_len = int.from_bytes(length_data, 'big')
        
        # Read message
        msg = b''
        while len(msg) < msg_len:
            chunk = conn.recv(min(4096, msg_len - len(msg)))
            if not chunk:
                return None
            msg += chunk
        
        if chacha:
            msg = chacha.decrypt(msg)
        
        return json.loads(msg.decode('utf-8'))
    
    def _handshake(self, conn: socket.socket) -> ChaCha20:
        """
        Perform ElGamal key exchange with client.
        
        Protocol:
        1. Server sends its public key + certificate
        2. Client sends its public key
        3. Both derive shared secret -> session key
        4. Session key used for ChaCha20 channel
        """
        # Step 1: Send server public key and certificate
        server_data = {
            'public_key': {
                'p': self.public_key['p'],
                'g': self.public_key['g'],
                'y': self.public_key['y'],
            }
        }
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
        
        # Step 2: Receive client public key
        client_data = self._recv_message(conn)
        if not client_data:
            return None
        
        client_y = client_data['public_key']['y']
        
        # Step 3: Derive shared secret and session key
        shared_secret = self.elgamal.derive_shared_secret(client_y)
        session_key = self.elgamal.derive_session_key(shared_secret, 32)
        nonce = hashlib.sha256(
            str(shared_secret).encode() + b'nonce'
        ).digest()[:12]
        
        print(f"[SERVER] Handshake complete, session key derived")
        return ChaCha20(session_key, nonce)
    
    def _handle_client(self, conn: socket.socket, addr: tuple):
        """Handle a single client connection."""
        print(f"[SERVER] Connection from {addr}")
        
        try:
            # Perform handshake
            chacha = self._handshake(conn)
            if not chacha:
                print(f"[SERVER] Handshake failed with {addr}")
                return
            
            session = {'username': None, 'chacha': chacha}
            
            # Main command loop
            while True:
                request = self._recv_message(conn, chacha)
                if not request:
                    break
                
                cmd = request.get('command')
                response = {'status': 'error', 'message': 'Unknown command'}
                
                if cmd == 'register':
                    ok = self.auth.register(
                        request['username'], request['password']
                    )
                    response = {
                        'status': 'ok' if ok else 'error',
                        'message': 'Registered' if ok else 'User exists'
                    }
                
                elif cmd == 'login':
                    token = self.auth.login(
                        request['username'], request['password']
                    )
                    if token:
                        session['username'] = request['username']
                        session['token'] = token
                        response = {'status': 'ok', 'token': token}
                    else:
                        response = {
                            'status': 'error',
                            'message': 'Invalid credentials'
                        }
                
                elif cmd == 'upload':
                    if not session.get('username'):
                        response = {'status': 'error', 'message': 'Not authenticated'}
                    else:
                        filename = request['filename']
                        # Data comes as list of ints (bytes)
                        file_data = bytes(request['data'])
                        saved = self._store_file(
                            session['username'], filename, file_data
                        )
                        response = {
                            'status': 'ok' if saved else 'error',
                            'message': 'File uploaded' if saved else 'Upload failed'
                        }
                
                elif cmd == 'download':
                    if not session.get('username'):
                        response = {'status': 'error', 'message': 'Not authenticated'}
                    else:
                        file_data = self._retrieve_file(
                            session['username'], request['filename']
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
                
                elif cmd == 'list_files':
                    if not session.get('username'):
                        response = {'status': 'error', 'message': 'Not authenticated'}
                    else:
                        files = self._list_files(session['username'])
                        response = {'status': 'ok', 'files': files}
                
                elif cmd == 'rotate_key':
                    if not session.get('username'):
                        response = {'status': 'error', 'message': 'Not authenticated'}
                    else:
                        self._rotate_storage_key(session['username'])
                        response = {'status': 'ok', 'message': 'Key rotated'}
                
                elif cmd == 'quit':
                    response = {'status': 'ok', 'message': 'Goodbye'}
                    self._send_message(conn, response, chacha)
                    break
                
                self._send_message(conn, response, chacha)
        
        except Exception as e:
            print(f"[SERVER] Error with {addr}: {e}")
        finally:
            conn.close()
            print(f"[SERVER] Connection closed: {addr}")
    
    def _store_file(self, username: str, filename: str,
                    data: bytes) -> bool:
        """Encrypt and store a file using Blowfish CBC."""
        user_dir = os.path.join(self.STORAGE_DIR, username)
        os.makedirs(user_dir, exist_ok=True)
        filepath = os.path.join(user_dir, filename + '.enc')
        
        iv = os.urandom(8)
        ciphertext = self.blowfish.encrypt_cbc(data, iv)
        
        with open(filepath, 'wb') as f:
            f.write(iv + ciphertext)
        
        print(f"[SERVER] Stored encrypted file: {filename} for {username}")
        return True
    
    def _retrieve_file(self, username: str, filename: str) -> bytes:
        """Decrypt and retrieve a stored file."""
        filepath = os.path.join(self.STORAGE_DIR, username,
                                filename + '.enc')
        if not os.path.exists(filepath):
            return None
        
        with open(filepath, 'rb') as f:
            data = f.read()
        
        iv = data[:8]
        ciphertext = data[8:]
        return self.blowfish.decrypt_cbc(ciphertext, iv)
    
    def _list_files(self, username: str) -> list:
        """List files stored for a user."""
        user_dir = os.path.join(self.STORAGE_DIR, username)
        if not os.path.exists(user_dir):
            return []
        files = []
        for f in os.listdir(user_dir):
            if f.endswith('.enc'):
                files.append(f[:-4])  # Remove .enc extension
        return files
    
    def _rotate_storage_key(self, username: str):
        """
        Rotate the storage encryption key.
        Re-encrypts all files for the user with a new key.
        """
        user_dir = os.path.join(self.STORAGE_DIR, username)
        if not os.path.exists(user_dir):
            return
        
        old_blowfish = self.blowfish
        
        # Generate new key
        new_key = os.urandom(16)
        new_blowfish = Blowfish(new_key)
        
        # Re-encrypt all files
        for fname in os.listdir(user_dir):
            if not fname.endswith('.enc'):
                continue
            filepath = os.path.join(user_dir, fname)
            with open(filepath, 'rb') as f:
                data = f.read()
            
            # Decrypt with old key
            iv_old = data[:8]
            plaintext = old_blowfish.decrypt_cbc(data[8:], iv_old)
            
            # Re-encrypt with new key
            iv_new = os.urandom(8)
            ciphertext = new_blowfish.encrypt_cbc(plaintext, iv_new)
            
            with open(filepath, 'wb') as f:
                f.write(iv_new + ciphertext)
        
        # Update key
        self.storage_key = new_key
        self.blowfish = new_blowfish
        with open(self.STORAGE_KEY_FILE, 'wb') as f:
            f.write(new_key)
        
        print(f"[SERVER] Storage key rotated for {username}")
    
    def start(self):
        """Start the server (blocking)."""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        self.running = True
        print(f"[SERVER] Listening on {self.host}:{self.port}")
        
        try:
            while self.running:
                self.server_socket.settimeout(1.0)
                try:
                    conn, addr = self.server_socket.accept()
                    t = threading.Thread(target=self._handle_client,
                                        args=(conn, addr), daemon=True)
                    t.start()
                except socket.timeout:
                    continue
        except KeyboardInterrupt:
            pass
        finally:
            self.stop()
    
    def stop(self):
        """Stop the server."""
        self.running = False
        if self.server_socket:
            self.server_socket.close()
        print("[SERVER] Stopped")
