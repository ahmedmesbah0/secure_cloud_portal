"""Demo: ElGamal encryption, signatures, and key exchange."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crypto.elgamal import ElGamal

BITS = 256  # Small for demo speed

print("=" * 50)
print("  ELGAMAL CRYPTOSYSTEM DEMO")
print("=" * 50)

# Key Generation
print("\n--- Key Generation ---")
eg = ElGamal(bits=BITS)
pub = eg.get_public_key()
priv = eg.get_private_key()
print(f"Prime p ({BITS} bits): {pub['p']}")
print(f"Generator g: {pub['g']}")
print(f"Public key y: {pub['y']}")
print(f"Private key x: {priv['x']}")

# Encryption
print("\n--- Encryption ---")
message = 42
c1, c2 = eg.encrypt(pub, message)
print(f"Message: {message}")
print(f"Ciphertext: c1={c1}, c2={c2}")
dec = eg.decrypt(c1, c2)
print(f"Decrypted: {dec}")
print(f"Match: {dec == message} ✓")

# Digital Signature
print("\n--- Digital Signature ---")
msg = b"Transfer $1000 to Alice"
r, s = eg.sign(msg)
print(f"Message: {msg.decode()}")
print(f"Signature: r={r}, s={s}")
valid = ElGamal.verify_signature(pub, msg, (r, s))
print(f"Valid: {valid} ✓")

# Tampered message
valid_tampered = ElGamal.verify_signature(pub, b"Transfer $9999 to Eve", (r, s))
print(f"Tampered message valid: {valid_tampered} (correctly rejected) ✓")

# Key Exchange
print("\n--- Key Exchange ---")
import random
from crypto.utils import mod_pow

# Bob generates his key in the same group
bob_x = random.randrange(2, pub['p'] - 1)
bob_y = mod_pow(pub['g'], bob_x, pub['p'])

# Both derive shared secret
alice_secret = eg.derive_shared_secret(bob_y)
bob_secret = mod_pow(pub['y'], bob_x, pub['p'])
print(f"Alice's shared secret: {alice_secret}")
print(f"Bob's shared secret:   {bob_secret}")
print(f"Match: {alice_secret == bob_secret} ✓")

# Derive session key
session_key = eg.derive_session_key(alice_secret, 32)
print(f"Session key (32 bytes): {session_key.hex()}")
