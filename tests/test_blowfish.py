"""Unit tests for Blowfish cipher."""
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crypto.blowfish import Blowfish


def test_ecb_basic():
    """Test ECB mode encrypt/decrypt."""
    bf = Blowfish(b'testkey!')
    plaintext = b'Hello World! This is a Blowfish test.'
    ct = bf.encrypt_ecb(plaintext)
    pt = bf.decrypt_ecb(ct)
    assert pt == plaintext, f"ECB failed: {pt}"
    print("  ✓ ECB encrypt/decrypt")


def test_cbc_basic():
    """Test CBC mode encrypt/decrypt."""
    bf = Blowfish(b'anothertestkey')
    iv = os.urandom(8)
    plaintext = b'CBC mode test with chaining.'
    ct = bf.encrypt_cbc(plaintext, iv)
    pt = bf.decrypt_cbc(ct, iv)
    assert pt == plaintext, f"CBC failed: {pt}"
    print("  ✓ CBC encrypt/decrypt")


def test_cbc_different_ivs():
    """Same plaintext with different IVs should produce different ciphertexts."""
    bf = Blowfish(b'samekey1234')
    plaintext = b'Same plaintext here'
    iv1 = os.urandom(8)
    iv2 = os.urandom(8)
    ct1 = bf.encrypt_cbc(plaintext, iv1)
    ct2 = bf.encrypt_cbc(plaintext, iv2)
    assert ct1 != ct2, "Different IVs should give different ciphertexts"
    print("  ✓ Different IVs produce different ciphertexts")


def test_different_keys():
    """Different keys should produce different ciphertexts."""
    bf1 = Blowfish(b'key1key1')
    bf2 = Blowfish(b'key2key2')
    iv = b'\x00' * 8
    plaintext = b'Same data'
    ct1 = bf1.encrypt_cbc(plaintext, iv)
    ct2 = bf2.encrypt_cbc(plaintext, iv)
    assert ct1 != ct2, "Different keys should give different ciphertexts"
    print("  ✓ Different keys produce different ciphertexts")


def test_empty_data():
    """Test encrypting empty data (still needs one padding block)."""
    bf = Blowfish(b'emptykey')
    iv = os.urandom(8)
    ct = bf.encrypt_cbc(b'', iv)
    pt = bf.decrypt_cbc(ct, iv)
    assert pt == b'', f"Empty data failed: {pt}"
    print("  ✓ Empty data encrypt/decrypt")


def test_file_encryption():
    """Test file encrypt/decrypt."""
    bf = Blowfish(b'fileenckey12345')
    os.makedirs('data', exist_ok=True)
    
    original = b'File content for encryption test.\nLine 2.\nLine 3.'
    with open('data/test_bf_in.txt', 'wb') as f:
        f.write(original)
    
    bf.encrypt_file('data/test_bf_in.txt', 'data/test_bf_enc.bin')
    bf.decrypt_file('data/test_bf_enc.bin', 'data/test_bf_out.txt')
    
    with open('data/test_bf_out.txt', 'rb') as f:
        result = f.read()
    
    assert result == original, "File encryption/decryption failed"
    
    # Cleanup
    for fn in ['data/test_bf_in.txt', 'data/test_bf_enc.bin', 'data/test_bf_out.txt']:
        os.remove(fn)
    print("  ✓ File encrypt/decrypt")


def test_large_data():
    """Test with larger data (1KB)."""
    bf = Blowfish(b'largedatakey')
    iv = os.urandom(8)
    plaintext = os.urandom(1024)
    ct = bf.encrypt_cbc(plaintext, iv)
    pt = bf.decrypt_cbc(ct, iv)
    assert pt == plaintext, "Large data test failed"
    print("  ✓ Large data (1KB) encrypt/decrypt")


def run_all():
    print("\n[TEST] Blowfish Tests")
    print("-" * 30)
    test_ecb_basic()
    test_cbc_basic()
    test_cbc_different_ivs()
    test_different_keys()
    test_empty_data()
    test_file_encryption()
    test_large_data()
    print("All Blowfish tests PASSED ✓\n")


if __name__ == '__main__':
    run_all()
