"""
Blowfish Block Cipher - Implemented From Scratch

Description:
------------
This is an educational implementation of the Blowfish symmetric block cipher.

Blowfish was designed by Bruce Schneier in 1993 and is based on a
16-round Feistel Network.

Features:
---------
- 64-bit block size (8 bytes)
- Variable key size (4 to 56 bytes)
- Key-dependent S-boxes
- ECB mode
- CBC mode with PKCS7 padding
- File encryption/decryption support

NOTE:
-----
This implementation is intended for educational purposes to demonstrate:
- Feistel Networks
- Key Scheduling
- Block Cipher Modes
- S-box Operations
- CBC Chaining

Not recommended for production cryptography.
"""

import os

from .blowfish_constants import (
    P_ORIG,
    S0_ORIG,
    S1_ORIG,
    S2_ORIG,
    S3_ORIG
)

from .utils import (
    pkcs7_pad,
    pkcs7_unpad,
    xor_bytes
)


class Blowfish:
    """
    Blowfish Symmetric Block Cipher

    Blowfish encrypts data using:
    - 16 Feistel rounds
    - Key-dependent S-boxes
    - 64-bit block size

    Supported modes:
    - ECB
    - CBC
    """

    BLOCK_SIZE = 8      # 64 bits
    ROUNDS = 16

    def __init__(self, key: bytes, debug: bool = False):
        """
        Initialize Blowfish Cipher

        Args:
            key: Encryption key (4 to 56 bytes)
            debug: Enables round tracing for educational purposes

        Key Schedule Process:
        ---------------------
        1. Copy original P-array and S-box constants
        2. XOR P-array with user key
        3. Encrypt all-zero blocks repeatedly
        4. Replace P-array and S-box values with encryption outputs
        """

        # Validate key length
        if not (4 <= len(key) <= 56):
            raise ValueError(
                "Key length must be between 4 and 56 bytes"
            )

        self.debug = debug

        # ==========================================================
        # Step 1: Initialize P-array and S-boxes
        # ==========================================================
        # These constants are derived from hexadecimal digits of PI
        # and are part of the official Blowfish specification.
        # ==========================================================

        self.P = list(P_ORIG)

        self.S = [
            list(S0_ORIG),
            list(S1_ORIG),
            list(S2_ORIG),
            list(S3_ORIG)
        ]

        # ==========================================================
        # Step 2: XOR user key into P-array
        # ==========================================================
        # The user key is cyclically repeated until all P-array
        # entries are modified.
        # ==========================================================

        key_len = len(key)
        j = 0

        for i in range(18):

            # Build 32-bit value from 4 key bytes
            val = 0

            for _ in range(4):
                val = ((val << 8) | key[j % key_len]) & 0xFFFFFFFF
                j += 1

            # Mix key into P-array
            self.P[i] ^= val

        # ==========================================================
        # Step 3: Generate final subkeys
        # ==========================================================
        # Repeatedly encrypt all-zero block and replace:
        # - P-array entries
        # - S-box entries
        #
        # This makes Blowfish heavily key-dependent.
        # ==========================================================

        L, R = 0, 0

        # Replace P-array values
        for i in range(0, 18, 2):
            L, R = self._encrypt_block(L, R)

            self.P[i] = L
            self.P[i + 1] = R

        # Replace S-box values
        for box in range(4):
            for i in range(0, 256, 2):

                L, R = self._encrypt_block(L, R)

                self.S[box][i] = L
                self.S[box][i + 1] = R

    # ==============================================================
    # Feistel Function
    # ==============================================================

    def _feistel(self, x: int) -> int:
        """
        Blowfish Feistel Function F(x)

        Mathematical Formula:
        ---------------------
        F(x) = ((S0[a] + S1[b]) XOR S2[c]) + S3[d]

        Steps:
        ------
        1. Split 32-bit input into four 8-bit values
        2. Use bytes as indices into S-boxes
        3. Combine outputs using addition and XOR

        This introduces:
        - confusion
        - nonlinearity
        """

        # Split 32-bit integer into 4 bytes
        a = (x >> 24) & 0xFF
        b = (x >> 16) & 0xFF
        c = (x >> 8) & 0xFF
        d = x & 0xFF

        # S-box lookups and nonlinear mixing
        result = (self.S[0][a] + self.S[1][b]) & 0xFFFFFFFF

        result ^= self.S[2][c]

        result = (result + self.S[3][d]) & 0xFFFFFFFF

        return result

    # ==============================================================
    # Block Encryption
    # ==============================================================

    def _encrypt_block(self, L: int, R: int) -> tuple:
        """
        Encrypt a single 64-bit block.

        Block Structure:
        ----------------
        Left Half  = 32 bits
        Right Half = 32 bits

        Blowfish uses a 16-round Feistel Network.

        Each round:
        -----------
        1. XOR left half with subkey
        2. Apply Feistel function
        3. XOR output into right half
        4. Swap halves
        """

        for i in range(self.ROUNDS):

            # XOR left half with round key
            L ^= self.P[i]

            # Apply Feistel function
            R ^= self._feistel(L)

            # Swap halves
            L, R = R, L

            # Optional debug tracing
            if self.debug:
                print(
                    f"[ENC ROUND {i+1}] "
                    f"L={hex(L)} "
                    f"R={hex(R)}"
                )

        # Undo last swap
        L, R = R, L

        # Final whitening
        R ^= self.P[16]
        L ^= self.P[17]

        return L, R

    # ==============================================================
    # Block Decryption
    # ==============================================================

    def _decrypt_block(self, L: int, R: int) -> tuple:
        """
        Decrypt a single 64-bit block.

        Feistel networks are reversible.
        Decryption uses the same structure as encryption,
        but traverses subkeys in reverse order.
        """

        for i in range(self.ROUNDS + 1, 1, -1):

            L ^= self.P[i]

            R ^= self._feistel(L)

            L, R = R, L

            if self.debug:
                print(
                    f"[DEC ROUND {i}] "
                    f"L={hex(L)} "
                    f"R={hex(R)}"
                )

        # Undo final swap
        L, R = R, L

        # Reverse final whitening
        R ^= self.P[1]
        L ^= self.P[0]

        return L, R

    # ==============================================================
    # Byte Conversion Helpers
    # ==============================================================

    def _bytes_to_block(self, data: bytes) -> tuple:
        """
        Convert 8 bytes into two 32-bit integers.

        Example:
            b'ABCDEFGH'

        Becomes:
            L = first 4 bytes
            R = last 4 bytes
        """

        L = (
            (data[0] << 24)
            | (data[1] << 16)
            | (data[2] << 8)
            | data[3]
        )

        R = (
            (data[4] << 24)
            | (data[5] << 16)
            | (data[6] << 8)
            | data[7]
        )

        return L, R

    def _block_to_bytes(self, L: int, R: int) -> bytes:
        """
        Convert two 32-bit integers into 8 bytes.
        """

        return bytes([
            (L >> 24) & 0xFF,
            (L >> 16) & 0xFF,
            (L >> 8) & 0xFF,
            L & 0xFF,

            (R >> 24) & 0xFF,
            (R >> 16) & 0xFF,
            (R >> 8) & 0xFF,
            R & 0xFF,
        ])

    # ==============================================================
    # ECB MODE
    # ==============================================================

    def encrypt_ecb(self, plaintext: bytes) -> bytes:
        """
        Encrypt data using ECB mode.

        ECB:
        ----
        Each block is encrypted independently.

        WARNING:
        --------
        ECB is insecure for repeated plaintext patterns.
        """

        # Apply PKCS7 padding
        padded = pkcs7_pad(plaintext, self.BLOCK_SIZE)

        result = b''

        # Encrypt each block independently
        for i in range(0, len(padded), self.BLOCK_SIZE):

            block = padded[i:i + self.BLOCK_SIZE]

            L, R = self._bytes_to_block(block)

            L, R = self._encrypt_block(L, R)

            result += self._block_to_bytes(L, R)

        return result

    def decrypt_ecb(self, ciphertext: bytes) -> bytes:
        """
        Decrypt ECB ciphertext.
        """

        if len(ciphertext) % self.BLOCK_SIZE != 0:
            raise ValueError(
                "Ciphertext length must be multiple of 8"
            )

        result = b''

        for i in range(0, len(ciphertext), self.BLOCK_SIZE):

            block = ciphertext[i:i + self.BLOCK_SIZE]

            L, R = self._bytes_to_block(block)

            L, R = self._decrypt_block(L, R)

            result += self._block_to_bytes(L, R)

        return pkcs7_unpad(result)

    # ==============================================================
    # CBC MODE
    # ==============================================================

    def encrypt_cbc(self, plaintext: bytes, iv: bytes) -> bytes:
        """
        Encrypt data using CBC mode.

        CBC Formula:
        ------------
        Ci = Encrypt(Pi XOR C(i-1))

        First block uses IV instead of previous ciphertext.

        Advantages:
        -----------
        Prevents identical plaintext blocks from generating
        identical ciphertext blocks.
        """

        if len(iv) != self.BLOCK_SIZE:
            raise ValueError("IV must be exactly 8 bytes")

        padded = pkcs7_pad(plaintext, self.BLOCK_SIZE)

        result = b''

        # Initial chaining block
        prev_block = iv

        for i in range(0, len(padded), self.BLOCK_SIZE):

            plaintext_block = padded[i:i + self.BLOCK_SIZE]

            # XOR plaintext with previous ciphertext block
            chained_block = xor_bytes(
                plaintext_block,
                prev_block
            )

            # Encrypt chained block
            L, R = self._bytes_to_block(chained_block)

            L, R = self._encrypt_block(L, R)

            encrypted_block = self._block_to_bytes(L, R)

            result += encrypted_block

            # Update chaining value
            prev_block = encrypted_block

        return result

    def decrypt_cbc(self, ciphertext: bytes, iv: bytes) -> bytes:
        """
        Decrypt CBC ciphertext.

        CBC Decryption:
        ---------------
        Pi = Decrypt(Ci) XOR C(i-1)
        """

        if len(iv) != self.BLOCK_SIZE:
            raise ValueError("IV must be exactly 8 bytes")

        if len(ciphertext) % self.BLOCK_SIZE != 0:
            raise ValueError(
                "Ciphertext length must be multiple of 8"
            )

        result = b''

        prev_block = iv

        for i in range(0, len(ciphertext), self.BLOCK_SIZE):

            ciphertext_block = ciphertext[i:i + self.BLOCK_SIZE]

            # Decrypt current block
            L, R = self._bytes_to_block(ciphertext_block)

            L, R = self._decrypt_block(L, R)

            decrypted_block = self._block_to_bytes(L, R)

            # XOR with previous ciphertext block
            plaintext_block = xor_bytes(
                decrypted_block,
                prev_block
            )

            result += plaintext_block

            # Save current ciphertext block
            prev_block = ciphertext_block

        return pkcs7_unpad(result)

    # ==============================================================
    # FILE ENCRYPTION
    # ==============================================================

    def encrypt_file(
        self,
        input_path: str,
        output_path: str,
        iv: bytes = None
    ):
        """
        Encrypt file using CBC mode.

        The IV is prepended to the encrypted file.
        """

        # Generate random IV if not provided
        if iv is None:
            iv = os.urandom(self.BLOCK_SIZE)

        # Read plaintext file
        with open(input_path, 'rb') as f:
            plaintext = f.read()

        # Encrypt data
        ciphertext = self.encrypt_cbc(plaintext, iv)

        # Save: IV + ciphertext
        with open(output_path, 'wb') as f:
            f.write(iv + ciphertext)

        return iv

    def decrypt_file(
        self,
        input_path: str,
        output_path: str
    ):
        """
        Decrypt file encrypted using encrypt_file().
        """

        with open(input_path, 'rb') as f:
            data = f.read()

        if len(data) < self.BLOCK_SIZE:
            raise ValueError("Invalid encrypted file")

        # Extract IV
        iv = data[:self.BLOCK_SIZE]

        # Extract ciphertext
        ciphertext = data[self.BLOCK_SIZE:]

        # Decrypt
        plaintext = self.decrypt_cbc(ciphertext, iv)

        # Save decrypted file
        with open(output_path, 'wb') as f:
            f.write(plaintext)