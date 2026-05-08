"""Unit tests for ChaCha20 stream cipher."""
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crypto.chacha20 import ChaCha20


def test_encrypt_decrypt():
    """Basic encrypt/decrypt test."""
    key = os.urandom(32)
    nonce = os.urandom(12)
    plaintext = b'Hello ChaCha20!'
    ct = ChaCha20(key, nonce).encrypt(plaintext)
    pt = ChaCha20(key, nonce).decrypt(ct)
    assert pt == plaintext
    print("  ✓ Basic encrypt/decrypt")


def test_symmetric():
    """Encrypt and decrypt are the same operation (XOR is symmetric)."""
    key = os.urandom(32)
    nonce = os.urandom(12)
    data = b'XOR symmetry test'
    encrypted = ChaCha20(key, nonce).encrypt(data)
    decrypted = ChaCha20(key, nonce).encrypt(encrypted)  # encrypt again = decrypt
    assert decrypted == data
    print("  ✓ XOR symmetry (encrypt twice = original)")


def test_different_nonces():
    """Same key + different nonces should give different ciphertexts."""
    key = os.urandom(32)
    data = b'Same data'
    ct1 = ChaCha20(key, os.urandom(12)).encrypt(data)
    ct2 = ChaCha20(key, os.urandom(12)).encrypt(data)
    assert ct1 != ct2
    print("  ✓ Different nonces produce different ciphertexts")


def test_different_keys():
    """Different keys with same nonce should give different ciphertexts."""
    nonce = os.urandom(12)
    data = b'Same data'
    ct1 = ChaCha20(os.urandom(32), nonce).encrypt(data)
    ct2 = ChaCha20(os.urandom(32), nonce).encrypt(data)
    assert ct1 != ct2
    print("  ✓ Different keys produce different ciphertexts")


def test_no_expansion():
    """ChaCha20 is a stream cipher - ciphertext same length as plaintext."""
    key = os.urandom(32)
    nonce = os.urandom(12)
    for size in [1, 10, 64, 100, 1000]:
        data = os.urandom(size)
        ct = ChaCha20(key, nonce).encrypt(data)
        assert len(ct) == len(data), f"Size mismatch at {size}"
    print("  ✓ No ciphertext expansion (stream cipher)")


def test_multi_block():
    """Test with data spanning multiple 64-byte blocks."""
    key = os.urandom(32)
    nonce = os.urandom(12)
    data = os.urandom(200)  # > 3 blocks
    ct = ChaCha20(key, nonce).encrypt(data)
    pt = ChaCha20(key, nonce).decrypt(ct)
    assert pt == data
    print("  ✓ Multi-block encrypt/decrypt (200 bytes)")


def test_large_data():
    """Test with 10KB of data."""
    key = os.urandom(32)
    nonce = os.urandom(12)
    data = os.urandom(10240)
    ct = ChaCha20(key, nonce).encrypt(data)
    pt = ChaCha20(key, nonce).decrypt(ct)
    assert pt == data
    print("  ✓ Large data (10KB)")


def test_quarter_round():
    """Test quarter round with known values from RFC 7539."""
    state = [0x879531e0, 0xc5ecf37d, 0x516461b1, 0xc9a62f8a,
             0x44c20ef3, 0x3390af7f, 0xd9fc690b, 0x2a5f714c,
             0x53372767, 0xb00a5631, 0x974c541a, 0x359e9963,
             0x5c971061, 0x3d631689, 0x2098d9d6, 0x91dbd320]
    ChaCha20._quarter_round(state, 2, 7, 8, 13)
    assert state[2] == 0xbdb886dc
    assert state[7] == 0xcfacafd2
    assert state[8] == 0xe46bea80
    assert state[13] == 0xccc07c79
    print("  ✓ Quarter round (RFC 7539 test vector)")


def run_all():
    print("\n[TEST] ChaCha20 Tests")
    print("-" * 30)
    test_encrypt_decrypt()
    test_symmetric()
    test_different_nonces()
    test_different_keys()
    test_no_expansion()
    test_multi_block()
    test_large_data()
    test_quarter_round()
    print("All ChaCha20 tests PASSED ✓\n")


if __name__ == '__main__':
    run_all()
