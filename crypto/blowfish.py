"""
Blowfish Block Cipher - Implemented from scratch.

Blowfish is a symmetric block cipher designed by Bruce Schneier.
- Block size: 64 bits (8 bytes)
- Key size: 32 to 448 bits (4 to 56 bytes)
- Structure: 16-round Feistel network
- Uses key-dependent S-boxes

This implementation supports:
- ECB (Electronic Codebook) mode
- CBC (Cipher Block Chaining) mode with PKCS7 padding
"""

import os
from .blowfish_constants import P_ORIG, S0_ORIG, S1_ORIG, S2_ORIG, S3_ORIG
from .utils import pkcs7_pad, pkcs7_unpad, xor_bytes


class Blowfish:
    """
    Blowfish cipher supporting ECB and CBC modes.
    
    Usage:
        bf = Blowfish(key=b'mysecretkey')
        iv = os.urandom(8)
        ciphertext = bf.encrypt_cbc(b'Hello World!', iv)
        plaintext = bf.decrypt_cbc(ciphertext, iv)
    """
    
    BLOCK_SIZE = 8  # 64 bits
    ROUNDS = 16
    
    def __init__(self, key: bytes):
        """
        Initialize Blowfish with the given key (4-56 bytes).
        
        Key schedule:
        1. Copy original P-array and S-boxes from pi constants
        2. XOR P-array with key bytes (cycling through key)
        3. Repeatedly encrypt (0,0) to replace P-array and S-box entries
        """
        if not (4 <= len(key) <= 56):
            raise ValueError("Key must be 4-56 bytes")
        
        # Step 1: Copy original constants
        self.P = list(P_ORIG)
        self.S = [list(S0_ORIG), list(S1_ORIG), list(S2_ORIG), list(S3_ORIG)]
        
        # Step 2: XOR P-array with key (cycling through key bytes)
        key_len = len(key)
        j = 0
        for i in range(18):
            # Build a 32-bit value from 4 key bytes
            val = 0
            for _ in range(4):
                val = ((val << 8) | key[j % key_len]) & 0xFFFFFFFF
                j += 1
            self.P[i] ^= val
        
        # Step 3: Encrypt all-zero blocks to generate final P and S values
        L, R = 0, 0
        
        # Replace P-array (18 entries, 2 at a time = 9 encryptions)
        for i in range(0, 18, 2):
            L, R = self._encrypt_block(L, R)
            self.P[i] = L
            self.P[i + 1] = R
        
        # Replace S-boxes (4 boxes x 256 entries = 512 encryptions)
        for box in range(4):
            for i in range(0, 256, 2):
                L, R = self._encrypt_block(L, R)
                self.S[box][i] = L
                self.S[box][i + 1] = R
    
    def _feistel(self, x: int) -> int:
        """
        Feistel function F(x).
        
        Splits 32-bit input into 4 bytes (a, b, c, d).
        Combines S-box lookups: ((S0[a] + S1[b]) XOR S2[c]) + S3[d]
        All arithmetic is mod 2^32.
        """
        a = (x >> 24) & 0xFF
        b = (x >> 16) & 0xFF
        c = (x >> 8) & 0xFF
        d = x & 0xFF
        
        result = (self.S[0][a] + self.S[1][b]) & 0xFFFFFFFF
        result ^= self.S[2][c]
        result = (result + self.S[3][d]) & 0xFFFFFFFF
        return result
    
    def _encrypt_block(self, L: int, R: int) -> tuple:
        """
        Encrypt a single 64-bit block (two 32-bit halves).
        
        16 Feistel rounds:
        - XOR left half with P[i]
        - XOR right half with F(left)
        - Swap halves
        Then final swap and XOR with P[16], P[17].
        """
        for i in range(self.ROUNDS):
            L ^= self.P[i]
            R ^= self._feistel(L)
            L, R = R, L  # Swap
        
        # Undo last swap and apply final P entries
        L, R = R, L
        R ^= self.P[16]
        L ^= self.P[17]
        return L, R
    
    def _decrypt_block(self, L: int, R: int) -> tuple:
        """Decrypt a single 64-bit block (reverse the encryption rounds)."""
        for i in range(self.ROUNDS + 1, 1, -1):
            L ^= self.P[i]
            R ^= self._feistel(L)
            L, R = R, L
        
        L, R = R, L
        R ^= self.P[1]
        L ^= self.P[0]
        return L, R
    
    def _bytes_to_block(self, data: bytes) -> tuple:
        """Convert 8 bytes to (L, R) pair of 32-bit integers."""
        L = (data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3]
        R = (data[4] << 24) | (data[5] << 16) | (data[6] << 8) | data[7]
        return L, R
    
    def _block_to_bytes(self, L: int, R: int) -> bytes:
        """Convert (L, R) pair of 32-bit integers to 8 bytes."""
        return bytes([
            (L >> 24) & 0xFF, (L >> 16) & 0xFF, (L >> 8) & 0xFF, L & 0xFF,
            (R >> 24) & 0xFF, (R >> 16) & 0xFF, (R >> 8) & 0xFF, R & 0xFF,
        ])
    
    def encrypt_ecb(self, plaintext: bytes) -> bytes:
        """Encrypt data in ECB mode (applies PKCS7 padding)."""
        padded = pkcs7_pad(plaintext, self.BLOCK_SIZE)
        result = b''
        for i in range(0, len(padded), self.BLOCK_SIZE):
            L, R = self._bytes_to_block(padded[i:i + self.BLOCK_SIZE])
            L, R = self._encrypt_block(L, R)
            result += self._block_to_bytes(L, R)
        return result
    
    def decrypt_ecb(self, ciphertext: bytes) -> bytes:
        """Decrypt data in ECB mode (removes PKCS7 padding)."""
        if len(ciphertext) % self.BLOCK_SIZE != 0:
            raise ValueError("Ciphertext length must be multiple of 8")
        result = b''
        for i in range(0, len(ciphertext), self.BLOCK_SIZE):
            L, R = self._bytes_to_block(ciphertext[i:i + self.BLOCK_SIZE])
            L, R = self._decrypt_block(L, R)
            result += self._block_to_bytes(L, R)
        return pkcs7_unpad(result)
    
    def encrypt_cbc(self, plaintext: bytes, iv: bytes) -> bytes:
        """
        Encrypt data in CBC (Cipher Block Chaining) mode.
        
        CBC chains blocks together:
        - Each plaintext block is XORed with the previous ciphertext block
        - First block is XORed with the IV (Initialization Vector)
        - This means identical plaintexts produce different ciphertexts
        
        Args:
            plaintext: Data to encrypt
            iv: 8-byte initialization vector (should be random)
        """
        if len(iv) != self.BLOCK_SIZE:
            raise ValueError("IV must be 8 bytes")
        
        padded = pkcs7_pad(plaintext, self.BLOCK_SIZE)
        result = b''
        prev_block = iv
        
        for i in range(0, len(padded), self.BLOCK_SIZE):
            # XOR plaintext block with previous ciphertext block
            block = xor_bytes(padded[i:i + self.BLOCK_SIZE], prev_block)
            L, R = self._bytes_to_block(block)
            L, R = self._encrypt_block(L, R)
            encrypted = self._block_to_bytes(L, R)
            result += encrypted
            prev_block = encrypted  # Chain for next block
        
        return result
    
    def decrypt_cbc(self, ciphertext: bytes, iv: bytes) -> bytes:
        """
        Decrypt data in CBC mode.
        
        Reverse of encrypt_cbc:
        - Decrypt each block
        - XOR with previous ciphertext block (or IV for first block)
        """
        if len(iv) != self.BLOCK_SIZE:
            raise ValueError("IV must be 8 bytes")
        if len(ciphertext) % self.BLOCK_SIZE != 0:
            raise ValueError("Ciphertext length must be multiple of 8")
        
        result = b''
        prev_block = iv
        
        for i in range(0, len(ciphertext), self.BLOCK_SIZE):
            block = ciphertext[i:i + self.BLOCK_SIZE]
            L, R = self._bytes_to_block(block)
            L, R = self._decrypt_block(L, R)
            decrypted = self._block_to_bytes(L, R)
            # XOR with previous ciphertext block
            result += xor_bytes(decrypted, prev_block)
            prev_block = block  # Save for next block's XOR
        
        return pkcs7_unpad(result)
    
    def encrypt_file(self, input_path: str, output_path: str, iv: bytes = None):
        """Encrypt a file using CBC mode. Returns the IV used."""
        if iv is None:
            iv = os.urandom(self.BLOCK_SIZE)
        with open(input_path, 'rb') as f:
            plaintext = f.read()
        ciphertext = self.encrypt_cbc(plaintext, iv)
        with open(output_path, 'wb') as f:
            f.write(iv + ciphertext)  # Prepend IV to ciphertext
        return iv
    
    def decrypt_file(self, input_path: str, output_path: str):
        """Decrypt a file encrypted with encrypt_file (IV is prepended)."""
        with open(input_path, 'rb') as f:
            data = f.read()
        iv = data[:self.BLOCK_SIZE]
        ciphertext = data[self.BLOCK_SIZE:]
        plaintext = self.decrypt_cbc(ciphertext, iv)
        with open(output_path, 'wb') as f:
            f.write(plaintext)
