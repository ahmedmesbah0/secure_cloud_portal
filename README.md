# Secure Cloud Document Portal

A Python-based secure cloud document storage system implementing cryptographic algorithms **from scratch** — no external crypto libraries used.

## Features

| Feature | Algorithm | Description |
|---------|-----------|-------------|
| **Encryption at Rest** | Blowfish (CBC) | Files stored encrypted on server disk |
| **Encryption in Transit** | ChaCha20 | All client-server communication encrypted |
| **Key Exchange** | ElGamal | Secure session key derivation via DH |
| **Digital Signatures** | ElGamal | Certificate signing and verification |
| **Authentication** | SHA-256 + Salt | Secure password storage and login |
| **Certificate Authority** | ElGamal PKI | Certificate issuance, verification, revocation |
| **Key Rotation** | Blowfish | Re-encrypt stored files with new keys |
| **Multi-user Support** | All | Multiple clients with isolated storage |

## Architecture

```
┌─────────────┐       ┌──────────────┐       ┌──────────────┐
│   Client     │◄─────►│    Server    │◄─────►│   CA         │
│              │ ChaCha │              │       │              │
│ • Upload     │  20    │ • Auth       │ ElGamal│ • Issue certs│
│ • Download   │       │ • Store(BF)  │  sigs  │ • Verify     │
│ • Login      │       │ • Key rotate │       │ • Revoke     │
└─────────────┘       └──────────────┘       └──────────────┘
```

**Data Flow:**
1. CA generates root keypair → issues certificates to server and client
2. Client connects → ElGamal key exchange → derive session key
3. All commands sent over ChaCha20 encrypted channel
4. Files encrypted with Blowfish CBC before disk storage
5. Downloads reverse the process: Blowfish decrypt → ChaCha20 encrypt → send

## Quick Start

```bash
# Clone/navigate to project
cd secure_cloud_portal

# Run the full demo (recommended first run)
python main.py

# Run interactive mode
python main.py --interactive

# Run all tests
python run_all_tests.py

# Run benchmarks
python performance/benchmark.py

# Run individual demos
python examples/demo_blowfish.py
python examples/demo_chacha20.py
python examples/demo_elgamal.py
python examples/demo_small_numbers.py
python examples/demo_full_system.py
```

**Requirements:** Python 3.8+ (no external packages needed)

## Project Structure

```
secure_cloud_portal/
├── crypto/                      # Core crypto algorithms (from scratch)
│   ├── blowfish.py              # Blowfish cipher (ECB + CBC)
│   ├── blowfish_constants.py    # P-array and S-boxes from pi
│   ├── chacha20.py              # ChaCha20 stream cipher
│   ├── elgamal.py               # ElGamal encrypt/sign/key-exchange
│   └── utils.py                 # Padding, modular arithmetic, primes
├── ca/                          # Certificate Authority
│   └── certificate_authority.py # Issue, verify, revoke certificates
├── auth/                        # Authentication
│   └── auth_manager.py          # Registration, login, sessions
├── server/                      # Server application
│   └── server.py                # Socket server with dual encryption
├── client/                      # Client application
│   └── client.py                # Socket client with secure channel
├── tests/                       # Test suite (40+ tests)
│   ├── test_blowfish.py
│   ├── test_chacha20.py
│   ├── test_elgamal.py
│   ├── test_auth.py
│   ├── test_ca.py
│   └── test_integration.py
├── examples/                    # Demo scripts
│   ├── demo_blowfish.py
│   ├── demo_chacha20.py
│   ├── demo_elgamal.py
│   ├── demo_full_system.py
│   └── demo_small_numbers.py   # Hand-traceable examples
├── performance/
│   └── benchmark.py             # Speed and size comparisons
├── main.py                      # Entry point (demo + interactive)
├── run_all_tests.py             # Test runner
└── README.md
```

## Algorithm Details

### Blowfish (File Encryption at Rest)
- **Type:** Symmetric block cipher, 16-round Feistel network
- **Block size:** 64 bits (8 bytes)
- **Key size:** 32-448 bits
- **Mode:** CBC with PKCS7 padding
- **S-boxes:** 4 × 256 entries, key-dependent (initialized from pi)
- **Used for:** Encrypting files on server disk

### ChaCha20 (Communication Encryption in Transit)
- **Type:** Stream cipher (ARX-based)
- **Key size:** 256 bits (32 bytes)
- **Nonce:** 96 bits (12 bytes)
- **Operations:** Add, Rotate, XOR only (no S-boxes)
- **Rounds:** 20 (10 double-rounds)
- **Used for:** Encrypting all client ↔ server messages

### ElGamal (Key Exchange & Signatures)
- **Type:** Public-key cryptosystem (discrete log based)
- **Key size:** 512 bits (configurable)
- **Based on:** Diffie-Hellman problem
- **Used for:** Key exchange, digital signatures, certificate signing

## How It Satisfies Coursework Requirements

| Requirement | Implementation |
|-------------|---------------|
| Encryption at rest | Blowfish CBC encrypts files on disk |
| Encryption in transit | ChaCha20 encrypts socket communication |
| Authentication | Salted SHA-256 password hashing + sessions |
| Key management | ElGamal keygen, session keys, key rotation |
| CA simulation | Certificate issuance, verification, revocation |
| Key exchange | ElGamal/DH-based shared secret derivation |
| No crypto libraries | All algorithms coded from scratch |
| Only basic libraries | Uses: os, json, socket, hashlib, random, time, threading |

## Common Viva Questions & Answers

### Q1: How does Blowfish encryption work?
Blowfish is a 16-round Feistel network. It splits each 64-bit block into two 32-bit halves (L, R). Each round XORs L with a subkey P[i], passes it through the F function (which uses 4 key-dependent S-boxes), and XORs the result with R, then swaps. The key schedule XORs the P-array with key bytes, then encrypts successive zero blocks to generate the final P-array and S-boxes.

### Q2: Why use CBC mode instead of ECB?
ECB encrypts identical blocks to identical ciphertext, revealing patterns. CBC chains blocks together by XORing each plaintext block with the previous ciphertext block, so identical inputs produce different outputs. The IV ensures the first block is also randomized.

### Q3: How does ChaCha20 work?
ChaCha20 builds a 4×4 matrix of 32-bit words (constants + key + counter + nonce), applies 20 rounds of quarter-round mixing (Add-Rotate-XOR), adds the original state, and outputs 64 bytes of keystream. Plaintext is XORed with the keystream. Since XOR is symmetric, encryption and decryption are the same operation.

### Q4: Why is ChaCha20 considered secure?
It uses 256-bit keys and a 96-bit nonce. The quarter round provides strong diffusion through repeated ARX operations. After 20 rounds, every output bit depends on every input bit. It's resistant to timing attacks since it only uses constant-time operations (add, rotate, XOR).

### Q5: How does ElGamal encryption work?
Given public key (p, g, y) where y = g^x mod p:
- Encrypt: choose random k, compute c1 = g^k mod p, c2 = m × y^k mod p
- Decrypt: compute s = c1^x mod p, then m = c2 × s^(-1) mod p

### Q6: How does the key exchange work?
Both parties have ElGamal keypairs in the same group. Alice computes Bob's y^(her x) mod p, Bob computes Alice's y^(his x) mod p. Both get g^(x_a × x_b) mod p — the same shared secret, which is hashed to derive a session key.

### Q7: How are passwords stored securely?
Passwords are never stored in plaintext. We generate a random 16-byte salt, concatenate it with the password, and hash using SHA-256. The database stores (salt, hash). To verify, we recompute the hash with the stored salt and compare.

### Q8: What is a Certificate Authority?
A CA is a trusted entity that binds identities to public keys. It signs certificates using its private key. Anyone with the CA's public key can verify a certificate's authenticity. Our CA also supports certificate revocation.

### Q9: What is key rotation and why is it important?
Key rotation replaces the encryption key periodically. Old files are decrypted with the old key and re-encrypted with the new key. This limits damage if a key is compromised — only data encrypted after the last rotation is at risk.

### Q10: How does the Feistel function F work in Blowfish?
F takes a 32-bit input, splits it into 4 bytes (a, b, c, d), and computes: ((S0[a] + S1[b]) XOR S2[c]) + S3[d]. The S-boxes are key-dependent, making the function different for every key.

### Q11: What is the Miller-Rabin primality test?
A probabilistic test to check if a number is prime. It writes n-1 as 2^r × d, then for random witnesses a, checks if a^d ≡ 1 (mod n) or a^(2^i × d) ≡ -1 (mod n) for some i. With 20 witnesses, the probability of a false positive is < 2^(-40).

### Q12: What is PKCS7 padding?
PKCS7 pads data to a multiple of the block size by appending N bytes each with value N. For example, with block size 8 and 5-byte data, append 3 bytes of value 0x03. This is unambiguous — even full blocks get a full block of padding.

### Q13: What is the difference between symmetric and asymmetric encryption?
Symmetric (Blowfish, ChaCha20): same key for encrypt and decrypt. Fast but requires secure key sharing. Asymmetric (ElGamal): different keys (public/private). Slower but solves key distribution. We use both: asymmetric for key exchange, symmetric for data.

### Q14: Why use two different symmetric ciphers?
Blowfish (block cipher) is used for file storage — it's well-suited for data at rest with CBC mode. ChaCha20 (stream cipher) is used for communication — it's faster, has no padding overhead, and is ideal for streaming data.

### Q15: What is a safe prime and why use one?
A safe prime p = 2q + 1 where q is also prime. For ElGamal, the group order p-1 = 2q has only factors {1, 2, q, 2q}, making it hard for attackers to find subgroups to exploit. This strengthens the discrete log security.

## Submission Checklist

- [x] All algorithms implemented from scratch (no crypto libraries)
- [x] Only basic libraries used (os, json, socket, hashlib, random, time, threading)
- [x] Blowfish with ECB and CBC modes
- [x] ChaCha20 stream cipher
- [x] ElGamal encryption, signatures, and key exchange
- [x] Certificate Authority with issuance, verification, and revocation
- [x] User authentication with salted password hashing
- [x] Encrypted file upload and download
- [x] Key rotation with re-encryption
- [x] Multi-user support
- [x] Real socket-based client-server communication
- [x] Comprehensive test suite (40+ tests, all passing)
- [x] Performance benchmarks
- [x] Small-number examples for hand-tracing
- [x] Demo scripts for each component
- [x] Full system demo (single command: `python main.py`)
- [x] Interactive mode (`python main.py --interactive`)
- [x] Well-commented, modular, readable code
- [x] README with viva Q&A
