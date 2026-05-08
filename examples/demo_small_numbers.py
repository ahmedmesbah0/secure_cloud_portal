"""
Small number examples for handwritten work and viva demonstrations.

Uses tiny parameters so you can trace through algorithms by hand.
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crypto.utils import mod_pow, mod_inverse


def blowfish_small_example():
    """Demonstrate Blowfish Feistel structure with simple numbers."""
    print("=" * 50)
    print("BLOWFISH - Small Feistel Network Example")
    print("=" * 50)
    print()
    print("Blowfish uses a 16-round Feistel network.")
    print("Here's a simplified 2-round example:\n")

    L, R = 0x12345678, 0x9ABCDEF0
    print(f"Input:  L = 0x{L:08X}, R = 0x{R:08X}")

    # Simplified F function (just XOR with a constant for illustration)
    P = [0x11111111, 0x22222222, 0x33333333, 0x44444444]

    for i in range(2):
        L_new = L ^ P[i]
        F_val = ((L_new >> 16) + (L_new & 0xFFFF)) & 0xFFFFFFFF  # Simplified F
        R_new = R ^ F_val
        print(f"Round {i+1}:")
        print(f"  L XOR P[{i}] = 0x{L:08X} XOR 0x{P[i]:08X} = 0x{L_new:08X}")
        print(f"  F(0x{L_new:08X}) = 0x{F_val:08X}")
        print(f"  R XOR F = 0x{R:08X} XOR 0x{F_val:08X} = 0x{R_new:08X}")
        print(f"  Swap: L = 0x{R_new:08X}, R = 0x{L_new:08X}")
        L, R = R_new, L_new

    # Final swap
    L, R = R, L
    R ^= P[2]
    L ^= P[3]
    print(f"\nFinal:  L = 0x{L:08X}, R = 0x{R:08X}")
    print()


def chacha20_small_example():
    """Demonstrate ChaCha20 quarter round with small values."""
    print("=" * 50)
    print("CHACHA20 - Quarter Round Example")
    print("=" * 50)
    print()
    print("The quarter round performs 4 ARX operations:")
    print("  a += b; d ^= a; d <<<= 16")
    print("  c += d; b ^= c; b <<<= 12")
    print("  a += b; d ^= a; d <<<= 8")
    print("  c += d; b ^= c; b <<<= 7\n")

    a, b, c, d = 0x11111111, 0x01020304, 0x9b8d6f43, 0x01234567
    print(f"Before: a=0x{a:08X} b=0x{b:08X} c=0x{c:08X} d=0x{d:08X}")

    def rotl32(v, n):
        return ((v << n) | (v >> (32 - n))) & 0xFFFFFFFF

    a = (a + b) & 0xFFFFFFFF; d ^= a; d = rotl32(d, 16)
    print(f"Step 1: a=0x{a:08X} b=0x{b:08X} c=0x{c:08X} d=0x{d:08X}")
    c = (c + d) & 0xFFFFFFFF; b ^= c; b = rotl32(b, 12)
    print(f"Step 2: a=0x{a:08X} b=0x{b:08X} c=0x{c:08X} d=0x{d:08X}")
    a = (a + b) & 0xFFFFFFFF; d ^= a; d = rotl32(d, 8)
    print(f"Step 3: a=0x{a:08X} b=0x{b:08X} c=0x{c:08X} d=0x{d:08X}")
    c = (c + d) & 0xFFFFFFFF; b ^= c; b = rotl32(b, 7)
    print(f"Step 4: a=0x{a:08X} b=0x{b:08X} c=0x{c:08X} d=0x{d:08X}")
    print()


def elgamal_small_example():
    """Demonstrate ElGamal with small numbers you can verify by hand."""
    print("=" * 50)
    print("ELGAMAL - Small Number Example")
    print("=" * 50)
    print()

    # Use small, hand-verifiable numbers
    p = 23   # Prime
    g = 5    # Generator of Z*_23
    x = 6    # Private key

    y = mod_pow(g, x, p)  # Public key
    print(f"Key Generation:")
    print(f"  p = {p} (prime)")
    print(f"  g = {g} (generator)")
    print(f"  x = {x} (private key)")
    print(f"  y = g^x mod p = {g}^{x} mod {p} = {y}")
    print(f"  Public key: (p={p}, g={g}, y={y})")
    print(f"  Private key: x={x}")
    print()

    # Encryption
    m = 7    # Message
    k = 3    # Random ephemeral key
    c1 = mod_pow(g, k, p)
    c2 = (m * mod_pow(y, k, p)) % p
    print(f"Encryption (message m = {m}, random k = {k}):")
    print(f"  c1 = g^k mod p = {g}^{k} mod {p} = {c1}")
    print(f"  c2 = m * y^k mod p = {m} * {y}^{k} mod {p} = {c2}")
    print(f"  Ciphertext: (c1={c1}, c2={c2})")
    print()

    # Decryption
    s = mod_pow(c1, x, p)
    s_inv = mod_inverse(s, p)
    m_dec = (c2 * s_inv) % p
    print(f"Decryption:")
    print(f"  s = c1^x mod p = {c1}^{x} mod {p} = {s}")
    print(f"  s^(-1) mod p = {s_inv}")
    print(f"  m = c2 * s^(-1) mod p = {c2} * {s_inv} mod {p} = {m_dec}")
    print(f"  Recovered message: {m_dec}")
    assert m_dec == m, "Decryption failed!"
    print(f"  ✓ Matches original message m = {m}")
    print()

    # Signature (simplified)
    print(f"Signature Example:")
    h = 13  # Hash of message (pretend)
    print(f"  Message hash h = {h}")
    print(f"  Using k = {k} (must be coprime to p-1 = {p-1})")
    r = mod_pow(g, k, p)
    k_inv = mod_inverse(k, p - 1)
    s_sig = ((h - x * r) * k_inv) % (p - 1)
    print(f"  r = g^k mod p = {r}")
    print(f"  k^(-1) mod (p-1) = {k_inv}")
    print(f"  s = (h - x*r) * k^(-1) mod (p-1) = {s_sig}")
    print(f"  Signature: (r={r}, s={s_sig})")

    # Verify
    left = mod_pow(g, h, p)
    right = (mod_pow(y, r, p) * mod_pow(r, s_sig, p)) % p
    print(f"\nVerification:")
    print(f"  g^h mod p = {left}")
    print(f"  y^r * r^s mod p = {right}")
    print(f"  Match: {left == right} ✓")
    print()


def diffie_hellman_example():
    """Demonstrate Diffie-Hellman key exchange with small numbers."""
    print("=" * 50)
    print("DIFFIE-HELLMAN Key Exchange")
    print("=" * 50)
    print()

    p, g = 23, 5
    a, b = 6, 15  # Private keys

    A = mod_pow(g, a, p)  # Alice's public
    B = mod_pow(g, b, p)  # Bob's public

    print(f"Public parameters: p={p}, g={g}")
    print(f"\nAlice: private a={a}, public A = g^a mod p = {A}")
    print(f"Bob:   private b={b}, public B = g^b mod p = {B}")

    s_alice = mod_pow(B, a, p)
    s_bob = mod_pow(A, b, p)
    print(f"\nAlice computes: B^a mod p = {B}^{a} mod {p} = {s_alice}")
    print(f"Bob computes:   A^b mod p = {A}^{b} mod {p} = {s_bob}")
    print(f"Shared secret: {s_alice} (match: {s_alice == s_bob}) ✓")
    print()


if __name__ == '__main__':
    blowfish_small_example()
    chacha20_small_example()
    elgamal_small_example()
    diffie_hellman_example()
