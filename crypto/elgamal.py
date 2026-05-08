"""
ElGamal Cryptosystem - Implemented from scratch.

ElGamal provides:
- Public-key encryption (based on Diffie-Hellman key exchange)
- Digital signatures (similar to DSA)
- Key exchange (derive shared secrets)

Security is based on the difficulty of the Discrete Logarithm Problem.

Key components:
- p: large prime number
- g: generator of the multiplicative group mod p
- x: private key (random, 1 < x < p-1)
- y: public key (y = g^x mod p)
"""

import random
import hashlib
from .utils import (mod_pow, generate_safe_prime, find_generator,
                    mod_inverse, hash_to_int, generate_prime)


class ElGamal:
    """
    ElGamal cryptosystem for encryption, signatures, and key exchange.
    
    Usage:
        eg = ElGamal(bits=512)  # Generate new keypair
        pub = eg.get_public_key()
        priv = eg.get_private_key()
        
        # Encrypt/decrypt a number
        c1, c2 = eg.encrypt(pub, message_int)
        plaintext = eg.decrypt(priv, c1, c2)
        
        # Sign/verify
        sig = eg.sign(message_bytes)
        valid = ElGamal.verify_signature(pub, message_bytes, sig)
    """
    
    def __init__(self, bits: int = 512, p=None, g=None, x=None, y=None):
        """
        Initialize ElGamal. Either generate new keys or load existing ones.
        
        Args:
            bits: Bit size for prime generation (default 512)
            p, g, x, y: Existing key parameters (optional)
        """
        if p is not None and g is not None:
            # Load existing parameters
            self.p = p
            self.g = g
            self.x = x  # Private key (None for public-only)
            self.y = y if y else mod_pow(g, x, p)
        else:
            # Generate new keypair
            self.p = generate_safe_prime(bits)
            self.g = find_generator(self.p)
            self.x = random.randrange(2, self.p - 1)  # Private key
            self.y = mod_pow(self.g, self.x, self.p)   # Public key
    
    def get_public_key(self) -> dict:
        """Return public key as a dictionary."""
        return {'p': self.p, 'g': self.g, 'y': self.y}
    
    def get_private_key(self) -> dict:
        """Return private key as a dictionary."""
        return {'p': self.p, 'g': self.g, 'x': self.x, 'y': self.y}
    
    def encrypt(self, pub_key: dict, message: int) -> tuple:
        """
        Encrypt an integer message using recipient's public key.
        
        Algorithm:
        1. Choose random k (1 < k < p-1)
        2. c1 = g^k mod p         (ephemeral public key)
        3. c2 = message * y^k mod p (encrypted message)
        
        Returns (c1, c2) tuple.
        """
        p, g, y = pub_key['p'], pub_key['g'], pub_key['y']
        
        if message >= p:
            raise ValueError("Message must be less than p")
        
        # Choose random ephemeral key k
        k = random.randrange(2, p - 1)
        
        c1 = mod_pow(g, k, p)              # Ephemeral public key
        c2 = (message * mod_pow(y, k, p)) % p  # Encrypted message
        
        return c1, c2
    
    def decrypt(self, c1: int, c2: int) -> int:
        """
        Decrypt ciphertext (c1, c2) using private key.
        
        Algorithm:
        1. Compute shared secret: s = c1^x mod p
        2. Compute inverse: s_inv = s^(-1) mod p
        3. Recover message: m = c2 * s_inv mod p
        """
        if self.x is None:
            raise ValueError("Private key required for decryption")
        
        s = mod_pow(c1, self.x, self.p)       # Shared secret
        s_inv = mod_inverse(s, self.p)          # Modular inverse
        message = (c2 * s_inv) % self.p         # Recover message
        return message
    
    def sign(self, message: bytes) -> tuple:
        """
        Sign a message using the private key.
        
        ElGamal signature scheme:
        1. Hash the message to get h
        2. Choose random k coprime to p-1
        3. r = g^k mod p
        4. s = (h - x*r) * k^(-1) mod (p-1)
        
        Returns (r, s) signature tuple.
        """
        if self.x is None:
            raise ValueError("Private key required for signing")
        
        h = hash_to_int(message) % (self.p - 1)
        p_minus_1 = self.p - 1
        
        # Find k coprime to p-1
        while True:
            k = random.randrange(2, p_minus_1)
            try:
                k_inv = mod_inverse(k, p_minus_1)
                break
            except ValueError:
                continue  # k not coprime to p-1, try again
        
        r = mod_pow(self.g, k, self.p)
        s = ((h - self.x * r) * k_inv) % p_minus_1
        
        return r, s
    
    @staticmethod
    def verify_signature(pub_key: dict, message: bytes, signature: tuple) -> bool:
        """
        Verify a signature using the signer's public key.
        
        Verification: g^h ≡ y^r * r^s (mod p)
        
        Returns True if signature is valid.
        """
        p, g, y = pub_key['p'], pub_key['g'], pub_key['y']
        r, s = signature
        
        if not (0 < r < p):
            return False
        
        h = hash_to_int(message) % (p - 1)
        
        # Left side: g^h mod p
        left = mod_pow(g, h, p)
        
        # Right side: (y^r * r^s) mod p
        right = (mod_pow(y, r, p) * mod_pow(r, s, p)) % p
        
        return left == right
    
    def derive_shared_secret(self, other_public_y: int) -> int:
        """
        Derive a shared secret using Diffie-Hellman-like key exchange.
        
        Both parties compute: shared = other_y^my_x mod p
        This gives both parties the same value (g^(x1*x2) mod p).
        """
        if self.x is None:
            raise ValueError("Private key required")
        return mod_pow(other_public_y, self.x, self.p)
    
    def derive_session_key(self, shared_secret: int, key_len: int = 32) -> bytes:
        """
        Derive a session key from the shared secret using SHA-256.
        
        Args:
            shared_secret: The shared secret integer
            key_len: Desired key length in bytes (default 32 for ChaCha20)
        """
        # Convert shared secret to bytes and hash it
        secret_bytes = str(shared_secret).encode()
        key_material = hashlib.sha256(secret_bytes).digest()
        return key_material[:key_len]
    
    def encrypt_bytes(self, pub_key: dict, data: bytes) -> list:
        """
        Encrypt arbitrary bytes by encrypting each byte as an integer.
        Returns a list of (c1, c2) tuples.
        """
        return [self.encrypt(pub_key, b) for b in data]
    
    def decrypt_bytes(self, ciphertext_pairs: list) -> bytes:
        """Decrypt a list of (c1, c2) tuples back to bytes."""
        return bytes([self.decrypt(c1, c2) for c1, c2 in ciphertext_pairs])
    
    def to_dict(self) -> dict:
        """Serialize key parameters to a dictionary."""
        d = {'p': self.p, 'g': self.g, 'y': self.y}
        if self.x is not None:
            d['x'] = self.x
        return d
    
    @classmethod
    def from_dict(cls, d: dict):
        """Create an ElGamal instance from a dictionary."""
        return cls(p=d['p'], g=d['g'], x=d.get('x'), y=d['y'])
