"""
Post-Quantum Cryptography - Simple LWE-Based Scheme (From Scratch)

Description:
------------
This is an educational implementation of a lattice-based cryptosystem
using the Learning With Errors (LWE) problem.

Why is this quantum-safe?
-------------------------
Classical cryptography (like ElGamal) relies on problems like
Discrete Logarithm, which quantum computers can solve using
Shor's algorithm.

LWE relies on the hardness of finding a secret vector 's' given:
    b = A * s + e  (mod q)

where 'e' is a small random error vector. This problem is believed
to be hard even for quantum computers.

This module provides:
- Key generation (public/private keypair)
- Key Encapsulation (KEM): derive a shared secret securely
- Simple encryption/decryption of byte messages

Parameters:
-----------
- n: lattice dimension (security parameter)
- q: modulus (prime number)
- Error is sampled from a small range to make the problem hard

NOTE:
-----
This is a simplified, educational implementation to demonstrate
the core ideas behind lattice-based post-quantum cryptography.
Not recommended for production use.
"""

import random
import hashlib
import os


class QuantumSafe:
    """
    Simple LWE-based post-quantum cryptosystem.

    The Learning With Errors (LWE) problem:
        Given matrix A and vector b = A*s + e (mod q),
        find secret vector s.

    This is believed to be hard for both classical and quantum computers.

    Usage:
        qs = QuantumSafe(n=64, q=257)
        pub, priv = qs.keygen()

        # Key Encapsulation
        ciphertext, shared_key = qs.encapsulate(pub)
        shared_key2 = qs.decapsulate(priv, ciphertext)
        # shared_key == shared_key2

        # Encrypt/Decrypt bytes
        ct = qs.encrypt(pub, b"hello")
        pt = qs.decrypt(priv, ct)
    """

    def __init__(self, n: int = 64, q: int = 257):
        """
        Initialize the LWE-based cryptosystem.

        Args:
            n: Lattice dimension (higher = more secure, slower)
            q: Modulus (must be prime, q > 2*n recommended)

        Typical values:
            n=64,  q=257  -> fast, educational
            n=128, q=521  -> stronger security
        """
        self.n = n
        self.q = q

    # ==============================================================
    # Helper Functions
    # ==============================================================

    def _random_vector(self, length: int) -> list:
        """Generate a random vector with values in [0, q)."""
        return [random.randrange(0, self.q) for _ in range(length)]

    def _random_matrix(self, rows: int, cols: int) -> list:
        """Generate a random matrix with values in [0, q)."""
        return [self._random_vector(cols) for _ in range(rows)]

    def _error_vector(self, length: int) -> list:
        """
        Generate a small error vector.

        Errors are sampled from {-1, 0, 1} to keep them small
        relative to q. This is what makes LWE hard to solve.
        """
        return [random.choice([-1, 0, 1]) for _ in range(length)]

    def _mat_vec_mul(self, matrix: list, vector: list) -> list:
        """
        Matrix-vector multiplication mod q.

        Computes: result = matrix * vector (mod q)
        """
        result = []
        for row in matrix:
            val = 0
            for i in range(len(vector)):
                val += row[i] * vector[i]
            result.append(val % self.q)
        return result

    def _vec_add(self, a: list, b: list) -> list:
        """Vector addition mod q."""
        return [(a[i] + b[i]) % self.q for i in range(len(a))]

    def _vec_sub(self, a: list, b: list) -> list:
        """Vector subtraction mod q."""
        return [(a[i] - b[i]) % self.q for i in range(len(a))]

    def _inner_product(self, a: list, b: list) -> int:
        """Inner product of two vectors mod q."""
        result = 0
        for i in range(len(a)):
            result += a[i] * b[i]
        return result % self.q

    # ==============================================================
    # Key Generation
    # ==============================================================

    def keygen(self) -> tuple:
        """
        Generate a public/private keypair.

        Algorithm:
        ----------
        1. Generate random matrix A  (n x n)
        2. Generate secret vector s  (n elements, small values)
        3. Generate error vector e   (n elements, tiny noise)
        4. Compute b = A * s + e (mod q)

        Public key:  (A, b)
        Private key: (A, s)

        Security:
        ---------
        Given A and b, an attacker cannot recover s because
        of the added noise e. This is the LWE assumption.
        """
        # Random public matrix
        A = self._random_matrix(self.n, self.n)

        # Secret key: small random vector
        s = self._error_vector(self.n)
        # Ensure values are positive mod q
        s = [x % self.q for x in s]

        # Small error noise
        e = self._error_vector(self.n)

        # Public vector: b = A*s + e (mod q)
        As = self._mat_vec_mul(A, s)
        b = self._vec_add(As, e)

        public_key = {'A': A, 'b': b}
        private_key = {'A': A, 's': s}

        return public_key, private_key

    # ==============================================================
    # Key Encapsulation Mechanism (KEM)
    # ==============================================================

    def encapsulate(self, public_key: dict) -> tuple:
        """
        Encapsulate: generate a shared secret using the public key.

        Algorithm:
        ----------
        1. Generate a random 256-bit coin (the raw shared secret)
        2. For each bit of the coin, create an LWE ciphertext:
           - u = A^T * r + e1
           - v = <b, r> + e2 + bit * (q // 2)
        3. Hash the coin to derive the shared key

        Returns:
            (ciphertext, shared_key)

        The recipient can recover the same coin (and thus the
        same shared key) using their private key.
        """
        A = public_key['A']
        b = public_key['b']
        half_q = self.q // 2

        # Generate random 256-bit coin (32 bytes)
        coin = [random.randint(0, 1) for _ in range(256)]

        # Encrypt each bit of the coin
        ct_list = []
        for bit in coin:
            r = self._error_vector(self.n)
            r = [x % self.q for x in r]
            e1 = self._error_vector(self.n)
            e2 = random.choice([-1, 0, 1])

            A_T = [[A[j][i] for j in range(self.n)] for i in range(self.n)]
            Ar = self._mat_vec_mul(A_T, r)
            u = self._vec_add(Ar, e1)

            v = (self._inner_product(b, r) + e2 + bit * half_q) % self.q
            ct_list.append({'u': u, 'v': v})

        ciphertext = {'kem_bits': ct_list}

        # Derive shared key from coin
        coin_bytes = bytes([
            sum(coin[i*8 + j] << (7 - j) for j in range(8))
            for i in range(32)
        ])
        shared_key = self._derive_key(int.from_bytes(coin_bytes, 'big'))

        return ciphertext, shared_key

    def decapsulate(self, private_key: dict, ciphertext: dict) -> bytes:
        """
        Decapsulate: recover the shared secret using the private key.

        Algorithm:
        ----------
        For each encrypted coin bit:
        1. Compute d = v - <s, u> (mod q)
        2. Round d: if closer to q//2 -> bit=1, else bit=0
        3. Reassemble coin and hash to derive shared key

        Why this works:
        ---------------
        d = v - <s, u>
          = <b, r> + e2 + bit*(q//2) - <s, A^T*r + e1>
          = bit*(q//2) + (small noise)

        The rounding step recovers the original bit despite noise.
        """
        s = private_key['s']
        half_q = self.q // 2

        coin = []
        for ct in ciphertext['kem_bits']:
            u = ct['u']
            v = ct['v']

            su = self._inner_product(s, u)
            d = (v - su) % self.q

            dist_to_0 = min(d, self.q - d)
            dist_to_half = min(abs(d - half_q), self.q - abs(d - half_q))

            coin.append(1 if dist_to_half < dist_to_0 else 0)

        # Reassemble coin bytes and derive shared key
        coin_bytes = bytes([
            sum(coin[i*8 + j] << (7 - j) for j in range(8))
            for i in range(32)
        ])
        shared_key = self._derive_key(int.from_bytes(coin_bytes, 'big'))

        return shared_key

    # ==============================================================
    # Encryption / Decryption (Byte Messages)
    # ==============================================================

    def encrypt(self, public_key: dict, plaintext: bytes) -> dict:
        """
        Encrypt a byte message using the public key.

        Algorithm:
        ----------
        1. Encode each bit of the message as 0 or q//2
        2. For each bit, create an LWE ciphertext:
           - u = A^T * r + e1
           - v = <b, r> + e2 + bit * (q // 2)

        The q//2 offset ensures the bit can be recovered
        even in the presence of small noise.
        """
        A = public_key['A']
        b = public_key['b']

        # Convert plaintext to bits
        bits = []
        for byte in plaintext:
            for i in range(7, -1, -1):
                bits.append((byte >> i) & 1)

        # Encrypt each bit
        ciphertext_bits = []
        half_q = self.q // 2

        for bit in bits:
            # Fresh randomness for each bit
            r = self._error_vector(self.n)
            r = [x % self.q for x in r]

            e1 = self._error_vector(self.n)
            e2 = random.choice([-1, 0, 1])

            # u = A^T * r + e1
            A_T = [[A[j][i] for j in range(self.n)] for i in range(self.n)]
            Ar = self._mat_vec_mul(A_T, r)
            u = self._vec_add(Ar, e1)

            # v = <b, r> + e2 + bit * (q // 2)
            v = (self._inner_product(b, r) + e2 + bit * half_q) % self.q

            ciphertext_bits.append({'u': u, 'v': v})

        return {
            'bits': ciphertext_bits,
            'length': len(plaintext)
        }

    def decrypt(self, private_key: dict, ciphertext: dict) -> bytes:
        """
        Decrypt ciphertext using the private key.

        Algorithm:
        ----------
        For each encrypted bit:
        1. Compute d = v - <s, u> (mod q)
        2. If d is closer to q//2 than to 0, the bit is 1
           Otherwise, the bit is 0

        Why this works:
        ---------------
        d = v - <s, u>
          = <b, r> + e2 + bit*(q//2) - <s, A^T*r + e1>
          = bit*(q//2) + (small noise)

        The noise is small, so:
        - If bit=0: d ≈ 0
        - If bit=1: d ≈ q//2
        """
        s = private_key['s']
        half_q = self.q // 2

        bits = []

        for ct in ciphertext['bits']:
            u = ct['u']
            v = ct['v']

            # Compute v - <s, u> mod q
            su = self._inner_product(s, u)
            d = (v - su) % self.q

            # Decide: is d closer to 0 or to q//2?
            dist_to_0 = min(d, self.q - d)
            dist_to_half = min(abs(d - half_q), self.q - abs(d - half_q))

            if dist_to_half < dist_to_0:
                bits.append(1)
            else:
                bits.append(0)

        # Convert bits back to bytes
        result = bytearray()
        msg_len = ciphertext['length']

        for i in range(0, msg_len * 8, 8):
            byte = 0
            for j in range(8):
                byte = (byte << 1) | bits[i + j]
            result.append(byte)

        return bytes(result)

    # ==============================================================
    # Key Derivation
    # ==============================================================

    def _derive_key(self, value: int, key_len: int = 32) -> bytes:
        """
        Derive a symmetric key from an integer using SHA-256.

        Args:
            value: Integer to derive key from
            key_len: Desired key length in bytes (default 32)
        """
        value_bytes = str(value).encode()
        return hashlib.sha256(value_bytes).digest()[:key_len]

    # ==============================================================
    # Serialization
    # ==============================================================

    def to_dict(self) -> dict:
        """Serialize parameters to a dictionary."""
        return {'n': self.n, 'q': self.q}

    @classmethod
    def from_dict(cls, d: dict):
        """Create a QuantumSafe instance from a dictionary."""
        return cls(n=d['n'], q=d['q'])
