"""Demo: ChaCha20 stream cipher for data in transit."""
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crypto.chacha20 import ChaCha20

print("=" * 50)
print("  CHACHA20 STREAM CIPHER DEMO")
print("=" * 50)

key = os.urandom(32)
nonce = os.urandom(12)
print(f"\nKey (hex): {key.hex()}")
print(f"Nonce (hex): {nonce.hex()}")
print(f"Key size: {len(key) * 8} bits")
print(f"Nonce size: {len(nonce) * 8} bits")

# Encrypt
message = b'Hello! This message is encrypted in transit using ChaCha20.'
print(f"\nPlaintext: {message.decode()}")
print(f"Plaintext length: {len(message)} bytes")

cipher = ChaCha20(key, nonce)
ciphertext = cipher.encrypt(message)
print(f"\nCiphertext (hex): {ciphertext.hex()}")
print(f"Ciphertext length: {len(ciphertext)} bytes")
print(f"No expansion: {len(ciphertext) == len(message)} ✓ (stream cipher)")

# Decrypt
decrypted = ChaCha20(key, nonce).decrypt(ciphertext)
print(f"\nDecrypted: {decrypted.decode()}")
print(f"Match: {decrypted == message} ✓")

# Show that encrypt and decrypt are the same operation
re_encrypted = ChaCha20(key, nonce).encrypt(ciphertext)
print(f"\nXOR property: encrypt(ciphertext) = plaintext: {re_encrypted == message} ✓")

# Different nonces produce different ciphertexts
nonce2 = os.urandom(12)
ct2 = ChaCha20(key, nonce2).encrypt(message)
print(f"\nSame message, different nonce:")
print(f"  CT1: {ciphertext[:16].hex()}...")
print(f"  CT2: {ct2[:16].hex()}...")
print(f"  Different: {ciphertext != ct2} ✓")
