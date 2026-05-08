"""
Utility functions for cryptographic operations.
Provides padding, byte conversion, prime generation, and helper functions
used across all modules.
"""

import random
import hashlib
import os


def pkcs7_pad(data: bytes, block_size: int) -> bytes:
    """Apply PKCS#7 padding to data so its length is a multiple of block_size."""
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)


def pkcs7_unpad(data: bytes) -> bytes:
    """Remove PKCS#7 padding from data."""
    if len(data) == 0:
        raise ValueError("Cannot unpad empty data")
    pad_len = data[-1]
    if pad_len == 0 or pad_len > len(data):
        raise ValueError(f"Invalid padding length: {pad_len}")
    for i in range(pad_len):
        if data[-(i + 1)] != pad_len:
            raise ValueError("Invalid PKCS#7 padding")
    return data[:-pad_len]


def bytes_to_int(b: bytes) -> int:
    """Convert bytes to a big-endian integer."""
    result = 0
    for byte in b:
        result = (result << 8) | byte
    return result


def int_to_bytes(n: int, length: int) -> bytes:
    """Convert an integer to big-endian bytes of specified length."""
    result = []
    for _ in range(length):
        result.append(n & 0xFF)
        n >>= 8
    return bytes(reversed(result))


def xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR two byte strings of equal length."""
    return bytes(x ^ y for x, y in zip(a, b))


def rotate_left_32(value: int, n: int) -> int:
    """Rotate a 32-bit integer left by n bits."""
    return ((value << n) | (value >> (32 - n))) & 0xFFFFFFFF


def mod_pow(base: int, exponent: int, modulus: int) -> int:
    """
    Fast modular exponentiation: (base^exponent) mod modulus.
    Uses square-and-multiply algorithm.
    """
    if modulus == 1:
        return 0
    result = 1
    base = base % modulus
    while exponent > 0:
        if exponent & 1:
            result = (result * base) % modulus
        exponent >>= 1
        base = (base * base) % modulus
    return result


def miller_rabin(n: int, k: int = 20) -> bool:
    """Miller-Rabin primality test with k witnesses."""
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = mod_pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = mod_pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_prime(bits: int) -> int:
    """Generate a random prime number of the specified bit length."""
    while True:
        n = random.getrandbits(bits)
        n |= (1 << (bits - 1)) | 1
        if miller_rabin(n):
            return n


def generate_safe_prime(bits: int) -> int:
    """Generate a safe prime p where p = 2q + 1 and q is also prime."""
    while True:
        q = generate_prime(bits - 1)
        p = 2 * q + 1
        if miller_rabin(p):
            return p


def find_generator(p: int) -> int:
    """Find a generator g for the multiplicative group mod safe prime p."""
    q = (p - 1) // 2
    for g in range(2, p):
        if mod_pow(g, 2, p) != 1 and mod_pow(g, q, p) != 1:
            return g
    raise ValueError("No generator found")


def extended_gcd(a: int, b: int):
    """Extended Euclidean Algorithm. Returns (gcd, x, y) where a*x + b*y = gcd."""
    if a == 0:
        return b, 0, 1
    g, x, y = extended_gcd(b % a, a)
    return g, y - (b // a) * x, x


def mod_inverse(a: int, m: int) -> int:
    """Compute modular multiplicative inverse of a mod m."""
    if m == 1:
        return 0
    g, x, _ = extended_gcd(a % m, m)
    if g != 1:
        raise ValueError(f"No modular inverse: gcd({a}, {m}) = {g}")
    return x % m


def hash_to_int(data: bytes) -> int:
    """Hash data using SHA-256 and return as an integer."""
    return int(hashlib.sha256(data).hexdigest(), 16)


def random_bytes(n: int) -> bytes:
    """Generate n random bytes using os.urandom."""
    return os.urandom(n)
