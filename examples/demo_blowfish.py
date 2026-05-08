"""Demo: Blowfish file encryption at rest."""
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crypto.blowfish import Blowfish

print("=" * 50)
print("  BLOWFISH FILE ENCRYPTION DEMO")
print("=" * 50)

# Setup
key = b'MySecretKey12345'
bf = Blowfish(key)
print(f"\nKey: {key}")
print(f"Block size: {bf.BLOCK_SIZE} bytes (64 bits)")
print(f"Rounds: {bf.ROUNDS}")

# Encrypt a message
plaintext = b'Confidential: Budget report Q4 2025 - Revenue $2.5M'
iv = os.urandom(8)
print(f"\nPlaintext: {plaintext.decode()}")
print(f"Plaintext bytes: {len(plaintext)}")
print(f"IV: {iv.hex()}")

ciphertext = bf.encrypt_cbc(plaintext, iv)
print(f"\nCiphertext (hex): {ciphertext.hex()}")
print(f"Ciphertext bytes: {len(ciphertext)}")
print(f"Expansion: {len(ciphertext) - len(plaintext)} bytes (PKCS7 padding)")

# Decrypt
decrypted = bf.decrypt_cbc(ciphertext, iv)
print(f"\nDecrypted: {decrypted.decode()}")
print(f"Match: {decrypted == plaintext} ✓")

# File encryption
print("\n--- File Encryption ---")
os.makedirs('data', exist_ok=True)
with open('data/demo_secret.txt', 'w') as f:
    f.write("TOP SECRET\nProject Alpha budget: $5,000,000\nLaunch date: June 2025")

bf.encrypt_file('data/demo_secret.txt', 'data/demo_secret.enc')
print("Encrypted: data/demo_secret.txt -> data/demo_secret.enc")

# Show encrypted file is unreadable
with open('data/demo_secret.enc', 'rb') as f:
    enc_data = f.read()
print(f"Encrypted file (first 40 hex chars): {enc_data[:20].hex()}")

bf.decrypt_file('data/demo_secret.enc', 'data/demo_decrypted.txt')
with open('data/demo_decrypted.txt', 'r') as f:
    print(f"\nDecrypted file content:\n{f.read()}")
print("✓ File encryption/decryption successful!")
