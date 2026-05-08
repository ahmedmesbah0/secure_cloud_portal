# Secure Cloud Document Portal — Report

## 1. Introduction

### 1.1 Problem Statement
Cloud storage systems require multiple layers of cryptographic protection to ensure confidentiality, integrity, and authenticity of user data. This project implements a secure cloud document portal with encryption at rest, encryption in transit, authentication, key management, and a simulated Certificate Authority.

### 1.2 Objectives
- Implement Blowfish, ChaCha20, and ElGamal algorithms from scratch
- Build a client-server document portal with dual encryption layers
- Simulate a PKI with a Certificate Authority
- Demonstrate secure key exchange and session management
- Provide comprehensive testing and performance analysis

### 1.3 Scope
The system handles document upload/download with encryption, user authentication, certificate-based trust, and key rotation. It uses Python standard libraries only — no external cryptographic packages.

---

## 2. Background

### 2.1 Symmetric Encryption — Blowfish
Blowfish is a symmetric block cipher designed by Bruce Schneier in 1993. It uses a 16-round Feistel network with 64-bit blocks and supports keys from 32 to 448 bits. The algorithm features key-dependent S-boxes, initialized from the hex digits of π and then modified through the key schedule process.

**Key concepts:** Feistel network, S-boxes, P-array, CBC mode, PKCS7 padding.

### 2.2 Stream Ciphers — ChaCha20
ChaCha20, designed by Daniel Bernstein, is a stream cipher using only Add-Rotate-XOR (ARX) operations. It takes a 256-bit key and 96-bit nonce, builds a 4×4 state matrix, and applies 20 rounds of quarter-round mixing to generate keystream blocks.

**Key concepts:** ARX operations, quarter round, keystream generation, XOR encryption.

### 2.3 Public Key Cryptography — ElGamal
The ElGamal cryptosystem, based on the Diffie-Hellman key exchange, provides both encryption and digital signatures. Security relies on the difficulty of the Discrete Logarithm Problem in finite fields.

**Key concepts:** Discrete logarithm, safe primes, generators, modular exponentiation.

### 2.4 Certificate Authorities
A CA is a trusted third party in a Public Key Infrastructure (PKI) that issues digital certificates binding public keys to identities. Our simulation implements certificate issuance, signature verification, and revocation.

---

## 3. System Design

### 3.1 Architecture
[Include architecture diagram from README]

### 3.2 Data Flow
1. CA generates root keypair and issues certificates
2. Client connects to server via TCP socket
3. ElGamal key exchange establishes shared session key
4. All subsequent communication encrypted with ChaCha20
5. Uploaded files encrypted with Blowfish CBC for storage
6. Downloads reverse the encryption layers

### 3.3 Threat Model
| Threat | Mitigation |
|--------|-----------|
| Eavesdropping on network | ChaCha20 encrypted channel |
| Server disk compromise | Blowfish CBC file encryption |
| Password theft | Salted SHA-256 hashing |
| Man-in-the-middle | Certificate-based authentication |
| Key compromise | Key rotation capability |
| Replay attacks | Random session keys + nonces |

---

## 4. Implementation

### 4.1 Blowfish
[Describe key schedule, Feistel rounds, F function, CBC mode implementation]

### 4.2 ChaCha20
[Describe state matrix, quarter round, block generation, keystream XOR]

### 4.3 ElGamal
[Describe key generation, encryption/decryption, signature scheme, key exchange]

### 4.4 Certificate Authority
[Describe certificate format, signing process, verification, revocation list]

### 4.5 Authentication
[Describe salt generation, password hashing, session token management]

### 4.6 Client-Server Communication
[Describe socket protocol, message framing, handshake sequence]

---

## 5. Testing

### 5.1 Unit Tests
- **Blowfish:** 7 tests (ECB, CBC, IVs, keys, padding, files, large data)
- **ChaCha20:** 8 tests (encrypt, symmetry, nonces, keys, expansion, multi-block, RFC vector)
- **ElGamal:** 8 tests (keygen, encrypt, sign, tamper, key exchange, session key, bytes, serialization)
- **Auth:** 10 tests (register, duplicate, login, wrong password, sessions, hashing)
- **CA:** 6 tests (issue, verify, tamper, revoke, multiple, root key)

### 5.2 Integration Test
Full system flow: CA setup → certificate issuance → client connection → handshake → registration → login → file upload → listing → download → integrity check → key rotation → re-download.

### 5.3 Results
All 40+ tests passing. [Include test output screenshot]

---

## 6. Performance Analysis

### 6.1 Encryption Speed
[Include benchmark table: Blowfish vs ChaCha20 at 1KB, 10KB, 100KB]

### 6.2 Ciphertext Expansion
[Include table showing plaintext vs ciphertext sizes for both algorithms]

### 6.3 Key Generation
[Include ElGamal keygen times at 256, 512 bits]

### 6.4 Observations
- ChaCha20 is faster for larger data (stream cipher advantage)
- Blowfish has padding overhead; ChaCha20 has zero expansion
- ElGamal keygen is the bottleneck (safe prime generation)

---

## 7. Conclusion
The project successfully implements a multi-layered cryptographic system using only Python standard libraries. All three algorithms (Blowfish, ChaCha20, ElGamal) work correctly as verified by comprehensive testing. The system demonstrates encryption at rest, encryption in transit, secure authentication, key management, and certificate authority simulation.

### Future Work
- Implement AES for comparison
- Add file integrity checking (HMAC)
- Support concurrent multi-user access
- Implement certificate chain of trust
- Add TLS-like protocol negotiation

---

## 8. References
1. Schneier, B. "Description of a New Variable-Length Key, 64-Bit Block Cipher (Blowfish)." 1993.
2. Bernstein, D.J. "ChaCha, a variant of Salsa20." 2008.
3. ElGamal, T. "A Public Key Cryptosystem and a Signature Scheme Based on Discrete Logarithms." 1985.
4. RFC 7539: "ChaCha20 and Poly1305 for IETF Protocols."
5. Menezes, A., van Oorschot, P., Vanstone, S. "Handbook of Applied Cryptography." CRC Press.
