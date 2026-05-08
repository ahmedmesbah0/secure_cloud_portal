"""Unit tests for ElGamal cryptosystem."""
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crypto.elgamal import ElGamal


# Use small bit size for fast tests
BITS = 256


def test_keygen():
    """Test key generation produces valid keys."""
    eg = ElGamal(bits=BITS)
    pub = eg.get_public_key()
    priv = eg.get_private_key()
    assert 'p' in pub and 'g' in pub and 'y' in pub
    assert 'x' in priv
    assert pub['y'] == pow(pub['g'], priv['x'], pub['p'])
    print("  ✓ Key generation")


def test_encrypt_decrypt():
    """Test encrypt/decrypt of integer message."""
    eg = ElGamal(bits=BITS)
    pub = eg.get_public_key()
    for msg in [0, 1, 42, 255, 12345]:
        c1, c2 = eg.encrypt(pub, msg)
        dec = eg.decrypt(c1, c2)
        assert dec == msg, f"Failed for message {msg}: got {dec}"
    print("  ✓ Encrypt/decrypt integers")


def test_sign_verify():
    """Test digital signature creation and verification."""
    eg = ElGamal(bits=BITS)
    pub = eg.get_public_key()
    message = b'This is a signed message'
    r, s = eg.sign(message)
    assert ElGamal.verify_signature(pub, message, (r, s))
    print("  ✓ Sign and verify")


def test_invalid_signature():
    """Tampered message should fail verification."""
    eg = ElGamal(bits=BITS)
    pub = eg.get_public_key()
    r, s = eg.sign(b'Original message')
    assert not ElGamal.verify_signature(pub, b'Tampered message', (r, s))
    print("  ✓ Tampered message fails verification")


def test_key_exchange():
    """Test Diffie-Hellman-like shared secret derivation."""
    # Two parties with same group parameters
    eg1 = ElGamal(bits=BITS)
    p, g = eg1.p, eg1.g

    # Create second party in same group
    import random
    from crypto.utils import mod_pow
    x2 = random.randrange(2, p - 1)
    y2 = mod_pow(g, x2, p)

    # Derive shared secrets
    secret1 = eg1.derive_shared_secret(y2)
    secret2 = mod_pow(eg1.y, x2, p)

    assert secret1 == secret2, "Shared secrets don't match"
    print("  ✓ Key exchange (shared secret)")


def test_session_key_derivation():
    """Test session key derivation from shared secret."""
    eg = ElGamal(bits=BITS)
    key32 = eg.derive_session_key(12345, 32)
    key16 = eg.derive_session_key(12345, 16)
    assert len(key32) == 32
    assert len(key16) == 16
    assert key32[:16] == key16  # First 16 bytes should match
    print("  ✓ Session key derivation")


def test_encrypt_bytes():
    """Test byte-level encryption/decryption."""
    eg = ElGamal(bits=BITS)
    pub = eg.get_public_key()
    data = b'Hi!'
    ct = eg.encrypt_bytes(pub, data)
    pt = eg.decrypt_bytes(ct)
    assert pt == data
    print("  ✓ Encrypt/decrypt bytes")


def test_serialization():
    """Test key serialization/deserialization."""
    eg = ElGamal(bits=BITS)
    d = eg.to_dict()
    eg2 = ElGamal.from_dict(d)
    assert eg2.p == eg.p
    assert eg2.g == eg.g
    assert eg2.x == eg.x
    assert eg2.y == eg.y
    print("  ✓ Key serialization")


def run_all():
    print("\n[TEST] ElGamal Tests")
    print("-" * 30)
    test_keygen()
    test_encrypt_decrypt()
    test_sign_verify()
    test_invalid_signature()
    test_key_exchange()
    test_session_key_derivation()
    test_encrypt_bytes()
    test_serialization()
    print("All ElGamal tests PASSED ✓\n")


if __name__ == '__main__':
    run_all()
