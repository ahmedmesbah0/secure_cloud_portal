"""
Performance Benchmark - Encryption speed, key generation, ciphertext expansion.

Measures and compares:
- Blowfish vs ChaCha20 encryption speed at various sizes
- ElGamal key generation time at various bit sizes
- Ciphertext size comparison
"""
import os
import sys
import time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crypto.blowfish import Blowfish
from crypto.chacha20 import ChaCha20
from crypto.elgamal import ElGamal


def benchmark_encryption():
    """Compare Blowfish and ChaCha20 encryption speeds."""
    print("=" * 60)
    print("  ENCRYPTION SPEED COMPARISON")
    print("=" * 60)
    print()

    bf_key = os.urandom(16)
    cc_key = os.urandom(32)
    cc_nonce = os.urandom(12)
    bf = Blowfish(bf_key)
    iv = os.urandom(8)

    sizes = [1024, 10240, 102400]  # 1KB, 10KB, 100KB
    labels = ['1 KB', '10 KB', '100 KB']

    print(f"{'Size':<10} {'Blowfish CBC':<20} {'ChaCha20':<20} {'Winner':<10}")
    print("-" * 60)

    for size, label in zip(sizes, labels):
        data = os.urandom(size)

        # Blowfish
        t0 = time.time()
        bf.encrypt_cbc(data, iv)
        bf_time = time.time() - t0

        # ChaCha20
        t0 = time.time()
        ChaCha20(cc_key, cc_nonce).encrypt(data)
        cc_time = time.time() - t0

        winner = "ChaCha20" if cc_time < bf_time else "Blowfish"
        print(f"{label:<10} {bf_time*1000:>8.2f} ms        "
              f"{cc_time*1000:>8.2f} ms        {winner}")

    print()


def benchmark_ciphertext_size():
    """Compare ciphertext expansion."""
    print("=" * 60)
    print("  CIPHERTEXT SIZE COMPARISON")
    print("=" * 60)
    print()

    bf = Blowfish(os.urandom(16))
    iv = os.urandom(8)
    cc_key = os.urandom(32)
    cc_nonce = os.urandom(12)

    sizes = [10, 50, 100, 500, 1000]
    print(f"{'Plaintext':<12} {'Blowfish CT':<15} {'BF Expansion':<15} "
          f"{'ChaCha20 CT':<15} {'CC Expansion':<15}")
    print("-" * 72)

    for size in sizes:
        data = os.urandom(size)
        bf_ct = bf.encrypt_cbc(data, iv)
        cc_ct = ChaCha20(cc_key, cc_nonce).encrypt(data)

        print(f"{size:<12} {len(bf_ct):<15} +{len(bf_ct)-size:<14} "
              f"{len(cc_ct):<15} +{len(cc_ct)-size:<14}")

    print()
    print("Note: Blowfish (block cipher) has padding overhead.")
    print("      ChaCha20 (stream cipher) has zero expansion.")
    print()


def benchmark_keygen():
    """Benchmark ElGamal key generation at various bit sizes."""
    print("=" * 60)
    print("  ELGAMAL KEY GENERATION TIME")
    print("=" * 60)
    print()

    bit_sizes = [256, 512]
    print(f"{'Bit Size':<12} {'Time':<15}")
    print("-" * 27)

    for bits in bit_sizes:
        t0 = time.time()
        ElGamal(bits=bits)
        elapsed = time.time() - t0
        print(f"{bits:<12} {elapsed:>8.3f} s")

    print()
    print("Note: Larger keys = more secure but slower generation.")
    print("      512-bit is used in this project for balance.")
    print("      Production systems use 2048+ bits.")
    print()


def benchmark_handshake():
    """Benchmark key exchange time."""
    print("=" * 60)
    print("  KEY EXCHANGE (HANDSHAKE) TIME")
    print("=" * 60)
    print()

    import random
    from crypto.utils import mod_pow

    for bits in [256, 512]:
        t0 = time.time()
        eg = ElGamal(bits=bits)
        keygen_time = time.time() - t0

        # Simulate key exchange
        t0 = time.time()
        other_x = random.randrange(2, eg.p - 1)
        other_y = mod_pow(eg.g, other_x, eg.p)
        secret = eg.derive_shared_secret(other_y)
        session_key = eg.derive_session_key(secret, 32)
        exchange_time = time.time() - t0

        print(f"{bits}-bit: keygen={keygen_time:.3f}s, "
              f"exchange={exchange_time:.3f}s, "
              f"total={keygen_time+exchange_time:.3f}s")

    print()


if __name__ == '__main__':
    print("\n" + "=" * 60)
    print("  SECURE CLOUD PORTAL - PERFORMANCE BENCHMARKS")
    print("=" * 60 + "\n")

    benchmark_encryption()
    benchmark_ciphertext_size()
    benchmark_keygen()
    benchmark_handshake()

    print("=" * 60)
    print("  BENCHMARKS COMPLETE")
    print("=" * 60)
