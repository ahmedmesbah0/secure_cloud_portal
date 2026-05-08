"""
Secure Cloud Client - Connects to the server with encrypted communication.

Handles:
- ElGamal key exchange (handshake) -> session key
- ChaCha20 encrypted communication
- Certificate verification via CA
- File upload/download commands
"""

import socket
import json
import hashlib
import os

from crypto.chacha20 import ChaCha20
from crypto.elgamal import ElGamal
from ca.certificate_authority import CertificateAuthority


class SecureClient:
    """
    Secure cloud client that communicates with the server.
    
    Usage:
        client = SecureClient('127.0.0.1', 5555, ca=ca_instance)
        client.connect()
        client.register('alice', 'password123')
        client.login('alice', 'password123')
        client.upload_file('test.txt')
        client.download_file('test.txt', 'downloaded_test.txt')
        client.disconnect()
    """
    
    def __init__(self, host: str = '127.0.0.1', port: int = 5555,
                 ca: CertificateAuthority = None, elgamal_bits: int = 512):
        self.host = host
        self.port = port
        self.ca = ca
        self.sock = None
        self.chacha = None
        self.token = None
        
        # Generate client's ElGamal keypair
        print("[CLIENT] Generating client keypair...")
        self.elgamal = ElGamal(bits=elgamal_bits)
        self.public_key = self.elgamal.get_public_key()
        
        # Get certificate from CA
        self.certificate = None
        if ca:
            self.certificate = ca.issue_certificate("client", self.public_key)
    
    def _send_message(self, data: dict, chacha: ChaCha20 = None):
        """Send a JSON message, optionally encrypted."""
        ch = chacha or self.chacha
        msg = json.dumps(data).encode('utf-8')
        if ch:
            msg = ch.encrypt(msg)
        length = len(msg).to_bytes(4, 'big')
        self.sock.sendall(length + msg)
    
    def _recv_message(self, chacha: ChaCha20 = None) -> dict:
        """Receive a JSON message, optionally decrypted."""
        ch = chacha or self.chacha
        length_data = b''
        while len(length_data) < 4:
            chunk = self.sock.recv(4 - len(length_data))
            if not chunk:
                return None
            length_data += chunk
        
        msg_len = int.from_bytes(length_data, 'big')
        msg = b''
        while len(msg) < msg_len:
            chunk = self.sock.recv(min(4096, msg_len - len(msg)))
            if not chunk:
                return None
            msg += chunk
        
        if ch:
            msg = ch.decrypt(msg)
        
        return json.loads(msg.decode('utf-8'))
    
    def _handshake(self) -> bool:
        """
        Perform ElGamal key exchange with server.
        
        1. Receive server's public key + certificate
        2. Verify certificate with CA
        3. Send client's public key
        4. Derive shared secret -> session key
        """
        # Step 1: Receive server public key
        server_data = self._recv_message(chacha=None)
        if not server_data:
            return False
        
        server_pub = server_data['public_key']
        
        # Step 2: Verify server certificate
        if self.ca and 'certificate' in server_data:
            cert = server_data['certificate']
            if self.ca.verify_certificate(cert):
                print("[CLIENT] Server certificate VERIFIED")
            else:
                print("[CLIENT] WARNING: Server certificate INVALID")
                return False
        
        # Step 3: Send client public key
        # We need to use the SAME p, g as server for key exchange
        # Create a client keypair in the server's group
        import random
        from crypto.utils import mod_pow
        
        p = server_pub['p']
        g = server_pub['g']
        client_x = random.randrange(2, p - 1)
        client_y = mod_pow(g, client_x, p)
        
        self._send_message({
            'public_key': {'p': p, 'g': g, 'y': client_y}
        }, chacha=None)
        
        # Step 4: Derive shared secret
        server_y = server_pub['y']
        shared_secret = mod_pow(server_y, client_x, p)
        
        # Derive session key (same method as server)
        secret_bytes = str(shared_secret).encode()
        session_key = hashlib.sha256(secret_bytes).digest()[:32]
        nonce = hashlib.sha256(
            str(shared_secret).encode() + b'nonce'
        ).digest()[:12]
        
        self.chacha = ChaCha20(session_key, nonce)
        print("[CLIENT] Handshake complete, secure channel established")
        return True
    
    def connect(self) -> bool:
        """Connect to server and establish secure channel."""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((self.host, self.port))
        print(f"[CLIENT] Connected to {self.host}:{self.port}")
        return self._handshake()
    
    def register(self, username: str, password: str) -> bool:
        """Register a new account."""
        self._send_message({
            'command': 'register',
            'username': username,
            'password': password,
        })
        resp = self._recv_message()
        print(f"[CLIENT] Register: {resp.get('message', resp.get('status'))}")
        return resp.get('status') == 'ok'
    
    def login(self, username: str, password: str) -> bool:
        """Login to the server."""
        self._send_message({
            'command': 'login',
            'username': username,
            'password': password,
        })
        resp = self._recv_message()
        if resp.get('status') == 'ok':
            self.token = resp.get('token')
            print(f"[CLIENT] Logged in as '{username}'")
            return True
        print(f"[CLIENT] Login failed: {resp.get('message')}")
        return False
    
    def upload_file(self, filepath: str) -> bool:
        """Upload a file to the server."""
        if not os.path.exists(filepath):
            print(f"[CLIENT] File not found: {filepath}")
            return False
        
        filename = os.path.basename(filepath)
        with open(filepath, 'rb') as f:
            data = f.read()
        
        self._send_message({
            'command': 'upload',
            'filename': filename,
            'data': list(data),
        })
        resp = self._recv_message()
        print(f"[CLIENT] Upload '{filename}': {resp.get('message', resp.get('status'))}")
        return resp.get('status') == 'ok'
    
    def download_file(self, filename: str, save_path: str = None) -> bool:
        """Download a file from the server."""
        self._send_message({
            'command': 'download',
            'filename': filename,
        })
        resp = self._recv_message()
        
        if resp.get('status') == 'ok':
            data = bytes(resp['data'])
            out_path = save_path or f"downloaded_{filename}"
            with open(out_path, 'wb') as f:
                f.write(data)
            print(f"[CLIENT] Downloaded '{filename}' -> '{out_path}'")
            return True
        
        print(f"[CLIENT] Download failed: {resp.get('message')}")
        return False
    
    def list_files(self) -> list:
        """List files stored on the server."""
        self._send_message({'command': 'list_files'})
        resp = self._recv_message()
        files = resp.get('files', [])
        print(f"[CLIENT] Files on server: {files}")
        return files
    
    def rotate_key(self) -> bool:
        """Request server to rotate storage key."""
        self._send_message({'command': 'rotate_key'})
        resp = self._recv_message()
        print(f"[CLIENT] Key rotation: {resp.get('message', resp.get('status'))}")
        return resp.get('status') == 'ok'
    
    def disconnect(self):
        """Disconnect from server."""
        try:
            self._send_message({'command': 'quit'})
            self._recv_message()
        except Exception:
            pass
        if self.sock:
            self.sock.close()
        print("[CLIENT] Disconnected")
