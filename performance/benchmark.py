"""
Performance Benchmark - Encryption speed, key generation, ciphertext expansion,
memory usage, and end-to-end system performance.

Measures and compares:
- Blowfish vs ChaCha20 encryption speed at various sizes
- ElGamal key generation time at various bit sizes
- Ciphertext size comparison
- Memory usage of each algorithm (via tracemalloc)
- End-to-end system performance (CA -> handshake -> upload -> download)
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


def benchmark_memory():
    """Measure peak memory usage of each algorithm."""
    import tracemalloc

    print("=" * 60)
    print("  MEMORY USAGE COMPARISON")
    print("=" * 60)
    print()

    data_10kb = os.urandom(10240)

    # --- Blowfish ---
    tracemalloc.start()
    bf = Blowfish(os.urandom(16))
    iv = os.urandom(8)
    _ = bf.encrypt_cbc(data_10kb, iv)
    bf_current, bf_peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    # --- ChaCha20 ---
    tracemalloc.start()
    cc = ChaCha20(os.urandom(32), os.urandom(12))
    _ = cc.encrypt(data_10kb)
    cc_current, cc_peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    # --- ElGamal (key generation only, 256-bit for speed) ---
    tracemalloc.start()
    eg = ElGamal(bits=256)
    eg_current, eg_peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    print(f"{'Algorithm':<20} {'Current':>12} {'Peak':>12}")
    print("-" * 44)
    print(f"{'Blowfish (10KB)':<20} {bf_current/1024:>9.1f} KB {bf_peak/1024:>9.1f} KB")
    print(f"{'ChaCha20 (10KB)':<20} {cc_current/1024:>9.1f} KB {cc_peak/1024:>9.1f} KB")
    print(f"{'ElGamal (256-bit)':<20} {eg_current/1024:>9.1f} KB {eg_peak/1024:>9.1f} KB")
    print()
    print("Note: Blowfish uses more memory due to 4 x 256-entry S-boxes.")
    print("      ChaCha20 has minimal memory footprint (no lookup tables).")
    print("      ElGamal memory depends on prime size and intermediate values.")
    print()


def benchmark_end_to_end():
    """
    Full end-to-end system benchmark.
    Times each phase: CA setup, server start, client connect + handshake,
    register, login, file upload, file download, disconnect.
    """
    import threading
    import shutil
    from ca.certificate_authority import CertificateAuthority
    from server.server import SecureServer
    from client.client import SecureClient

    print("=" * 60)
    print("  END-TO-END SYSTEM PERFORMANCE")
    print("=" * 60)
    print()

    BITS = 256  # Use smaller keys for benchmark speed
    PORT = 5580
    results = []

    # Ensure clean state
    for d in ['data', 'keys']:
        if os.path.exists(d):
            shutil.rmtree(d)

    # Phase 1: CA Setup
    t0 = time.time()
    ca = CertificateAuthority(bits=BITS)
    t_ca = time.time() - t0
    results.append(('CA Setup (keygen + init)', t_ca))

    # Phase 2: Server Start
    t0 = time.time()
    server = SecureServer(host='127.0.0.1', port=PORT, ca=ca, elgamal_bits=BITS)
    server_thread = threading.Thread(target=server.start, daemon=True)
    server_thread.start()
    time.sleep(0.5)
    t_server = time.time() - t0
    results.append(('Server Start (keygen + cert)', t_server))

    # Phase 3: Client Connect + Handshake
    t0 = time.time()
    client = SecureClient(host='127.0.0.1', port=PORT, ca=ca, elgamal_bits=BITS)
    client.connect()
    t_handshake = time.time() - t0
    results.append(('Client Connect + Handshake', t_handshake))

    # Phase 4: Register
    t0 = time.time()
    client.register('benchuser', 'benchpass')
    t_register = time.time() - t0
    results.append(('User Registration', t_register))

    # Phase 5: Login
    t0 = time.time()
    client.login('benchuser', 'benchpass')
    t_login = time.time() - t0
    results.append(('User Login', t_login))

    # Create test files of varying sizes
    os.makedirs('data', exist_ok=True)
    for size_label, size_bytes in [('1KB', 1024), ('10KB', 10240), ('100KB', 102400)]:
        test_file = f'data/bench_{size_label}.bin'
        with open(test_file, 'wb') as f:
            f.write(os.urandom(size_bytes))

        # Phase 6: Upload
        t0 = time.time()
        client.upload_file(test_file)
        t_upload = time.time() - t0
        results.append((f'Upload {size_label}', t_upload))

        # Phase 7: Download
        t0 = time.time()
        client.download_file(f'bench_{size_label}.bin',
                             f'data/downloaded_{size_label}.bin')
        t_download = time.time() - t0
        results.append((f'Download {size_label}', t_download))

    # Phase 8: Key Rotation
    t0 = time.time()
    client.rotate_key()
    t_rotate = time.time() - t0
    results.append(('Key Rotation (3 files)', t_rotate))

    # Phase 9: Disconnect
    t0 = time.time()
    client.disconnect()
    t_disconnect = time.time() - t0
    results.append(('Disconnect', t_disconnect))

    server.stop()

    # Print results table
    print()
    print(f"{'Phase':<35} {'Time':>12}")
    print("-" * 47)
    total = 0
    for phase, elapsed in results:
        total += elapsed
        if elapsed < 1.0:
            print(f"{phase:<35} {elapsed*1000:>9.2f} ms")
        else:
            print(f"{phase:<35} {elapsed:>9.3f} s ")
    print("-" * 47)
    print(f"{'TOTAL':<35} {total:>9.3f} s ")
    print()
    print("Note: Upload/download times include ChaCha20 encryption in")
    print("      transit AND Blowfish encryption at rest (dual-layer).")
    print("      Key rotation re-encrypts all stored files with a new key.")
    print()


if __name__ == '__main__':
    print("\n" + "=" * 60)
    print("  SECURE CLOUD PORTAL - PERFORMANCE BENCHMARKS")
    print("=" * 60 + "\n")

    benchmark_encryption()
    benchmark_ciphertext_size()
    benchmark_memory()
    benchmark_keygen()
    benchmark_handshake()
    benchmark_end_to_end()

    print("=" * 60)
    print("  BENCHMARKS COMPLETE")
    print("=" * 60)
