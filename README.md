# 🔐 Secure Cloud Document Portal

A **fully custom-built** secure cloud document storage system implemented entirely in Python — **without any external cryptographic libraries**. Every algorithm (Blowfish, ChaCha20, ElGamal) is hand-coded from scratch, demonstrating low-level cryptographic concepts in a real client-server application.

---

## 📑 Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Cryptographic Algorithms](#cryptographic-algorithms)
  - [Blowfish (Symmetric — Block Cipher)](#blowfish-symmetric--block-cipher)
  - [ChaCha20 (Symmetric — Stream Cipher)](#chacha20-symmetric--stream-cipher)
  - [ElGamal (Asymmetric — Public Key)](#elgamal-asymmetric--public-key)
- [Project Structure](#project-structure)
- [Features](#features)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Running the Full Demo](#running-the-full-demo)
  - [Interactive CLI Mode](#interactive-cli-mode)
  - [Web GUI Mode](#web-gui-mode)
- [Usage Examples](#usage-examples)
- [Testing](#testing)
- [Performance Benchmarks](#performance-benchmarks)
- [Security Design](#security-design)
- [Small Number Examples (For Viva)](#small-number-examples-for-viva)

---

## Overview

This project implements a complete secure file storage portal with **dual-layer encryption**:

| Layer | Algorithm | Purpose |
|-------|-----------|---------|
| **Data in Transit** | ChaCha20 (256-bit key) | Encrypts all client ↔ server communication |
| **Data at Rest** | Blowfish CBC (128-bit key) | Encrypts stored files on the server disk |
| **Key Exchange** | ElGamal / Diffie-Hellman | Establishes shared session keys without transmitting secrets |
| **Authentication** | Salted SHA-256 + SQLite | Secure password storage with random salts |
| **Identity Verification** | Certificate Authority (ElGamal signatures) | Issues and verifies digital certificates |

**Zero external crypto dependencies** — only Python's standard library (`socket`, `hashlib`, `sqlite3`, `os`, `json`, `random`, `threading`).

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     Certificate Authority (CA)                  │
│            ElGamal root keypair · Issues certificates            │
│            Signs & verifies identity bindings                    │
└──────────────────────┬─────────────────────┬────────────────────┘
                       │  cert               │  cert
              ┌────────▼────────┐   ┌────────▼────────┐
              │  Secure Server  │   │  Secure Client  │
              │                 │   │                 │
              │ • ElGamal keys  │◄──┤ • ElGamal keys  │
              │ • Auth Manager  │   │ • Handshake     │
              │ • Blowfish      │   │                 │
              │   (at rest)     │   │                 │
              └────────┬────────┘   └────────┬────────┘
                       │                     │
                       └──── ChaCha20 ───────┘
                        (encrypted channel)
              ┌─────────────────────────────────────┐
              │           SQLite Database            │
              │  users (salt + hash) │ files (meta)  │
              └─────────────────────────────────────┘
```

### Communication Flow

1. **CA Setup** — Generates a root ElGamal keypair
2. **Server Start** — Generates its own keypair, gets a certificate from the CA
3. **Client Connect** — Generates its own keypair, gets a certificate from the CA
4. **Handshake** — ElGamal key exchange derives a shared secret → ChaCha20 session key
5. **Secure Channel** — All subsequent messages are ChaCha20 encrypted
6. **File Upload** — Client sends file over encrypted channel → Server encrypts at rest with Blowfish CBC
7. **File Download** — Server decrypts from Blowfish → sends over encrypted ChaCha20 channel

---

## Cryptographic Algorithms

### Blowfish (Symmetric — Block Cipher)

| Property | Value |
|----------|-------|
| Block size | 64 bits (8 bytes) |
| Key size | 32–448 bits (4–56 bytes) |
| Structure | 16-round Feistel network |
| Modes | ECB, CBC with PKCS#7 padding |

**Implementation Details:**
- P-array (18 entries) and four S-boxes (256 entries each) derived from the hex digits of π
- Key schedule: XOR key bytes into P-array, then encrypt all-zeros repeatedly to generate final P and S values (521 encryptions during setup)
- Feistel function `F(x)`: splits 32-bit input into 4 bytes `(a,b,c,d)` → `((S0[a] + S1[b]) ⊕ S2[c]) + S3[d]`
- CBC mode: each plaintext block is XORed with the previous ciphertext block before encryption
- File encryption prepends the random IV to the ciphertext

**Files:** `crypto/blowfish.py`, `crypto/blowfish_constants.py`, `crypto/generate_bf_constants.py`

---

### ChaCha20 (Symmetric — Stream Cipher)

| Property | Value |
|----------|-------|
| Key size | 256 bits (32 bytes) |
| Nonce size | 96 bits (12 bytes) |
| Block output | 512 bits (64 bytes) of keystream |
| Operations | ARX: Add, Rotate, XOR |

**Implementation Details:**
- 4×4 state matrix of 32-bit words: `[constants | key | counter | nonce]`
- Quarter round performs 4 ARX steps with rotation amounts 16, 12, 8, 7
- 20 rounds = 10 double-rounds (column rounds + diagonal rounds)
- Final state = working state + initial state (mod 2³²)
- Encryption = `plaintext ⊕ keystream` (decryption is identical)
- Zero ciphertext expansion (stream cipher)

**Files:** `crypto/chacha20.py`

---

### ElGamal (Asymmetric — Public Key)

| Property | Value |
|----------|-------|
| Security basis | Discrete Logarithm Problem |
| Key components | `p` (safe prime), `g` (generator), `x` (private), `y = gˣ mod p` (public) |
| Operations | Encryption, Decryption, Digital Signatures, Key Exchange |

**Implementation Details:**
- Safe prime generation: `p = 2q + 1` where both `p` and `q` are prime
- Miller-Rabin primality test with 20 witnesses
- Modular exponentiation via square-and-multiply
- Encryption: `c1 = gᵏ mod p`, `c2 = m · yᵏ mod p`
- Decryption: `m = c2 · (c1ˣ)⁻¹ mod p`
- Signatures: `r = gᵏ mod p`, `s = (h - xr) · k⁻¹ mod (p-1)`
- Verification: `gʰ ≡ yʳ · rˢ (mod p)`
- Diffie-Hellman key exchange: shared secret = `other_y^my_x mod p`
- Session key derivation: SHA-256 hash of the shared secret

**Files:** `crypto/elgamal.py`, `crypto/utils.py`

---

## Project Structure

```
secure_cloud_portal/
│
├── main.py                        # Main entry point (demo / interactive / GUI)
├── gui_server.py                  # Web GUI HTTP backend (stdlib only)
├── gui_frontend.html              # Web GUI single-page frontend
├── run_all_tests.py               # Test suite runner
├── .gitignore
│
├── crypto/                        # All cryptographic algorithms (from scratch)
│   ├── __init__.py                # Package exports
│   ├── blowfish.py                # Blowfish block cipher (ECB + CBC)
│   ├── blowfish_constants.py      # P-array & S-boxes from digits of π
│   ├── generate_bf_constants.py   # Script to regenerate constants
│   ├── chacha20.py                # ChaCha20 stream cipher
│   ├── elgamal.py                 # ElGamal encryption, signatures, key exchange
│   └── utils.py                   # Shared utilities (padding, primes, modular math)
│
├── auth/                          # Authentication system
│   ├── __init__.py
│   └── auth_manager.py            # User registration, login, sessions (SQLite)
│
├── ca/                            # Certificate Authority simulation
│   ├── __init__.py
│   └── certificate_authority.py   # Certificate issuance, signing, verification
│
├── server/                        # Secure server
│   ├── __init__.py
│   └── server.py                  # TCP socket server with dual-layer encryption
│
├── client/                        # Secure client
│   ├── __init__.py
│   └── client.py                  # TCP socket client with handshake & commands
│
├── tests/                         # Test suite
│   ├── test_blowfish.py           # Blowfish unit tests (7 tests)
│   ├── test_chacha20.py           # ChaCha20 unit tests
│   ├── test_elgamal.py            # ElGamal unit tests
│   ├── test_auth.py               # Authentication unit tests
│   ├── test_ca.py                 # Certificate Authority unit tests
│   └── test_integration.py        # Full system integration test
│
├── performance/                   # Benchmarking suite
│   └── benchmark.py               # Speed, memory, ciphertext size, end-to-end benchmarks
│
├── examples/                      # Demonstration scripts
│   ├── demo_blowfish.py           # Standalone Blowfish demo
│   ├── demo_chacha20.py           # Standalone ChaCha20 demo
│   ├── demo_elgamal.py            # Standalone ElGamal demo
│   ├── demo_full_system.py        # Complete 10-phase system demo
│   └── demo_small_numbers.py      # Small number examples for hand verification
│
├── data/                          # Runtime data (auto-generated, gitignored)
│   ├── portal.db                  # SQLite database (users + file metadata)
│   └── files/                     # Encrypted file storage (per-user directories)
│
└── keys/                          # Runtime keys (auto-generated, gitignored)
    └── storage_key.bin            # Blowfish storage encryption key (128-bit)
```

---

## Features

- **Dual-Layer Encryption** — ChaCha20 in transit + Blowfish at rest
- **Custom ElGamal Key Exchange** — Diffie-Hellman style session key derivation
- **Certificate Authority** — Issues, signs, verifies, and revokes certificates
- **User Authentication** — Salted SHA-256 password hashing with SQLite persistence
- **Session Management** — Random token-based sessions with 1-hour expiry
- **File Upload / Download** — Encrypted end-to-end with integrity verification
- **Storage Key Rotation** — Re-encrypts all stored files with a new key
- **Multi-User Support** — Isolated per-user file storage
- **Web GUI** — Beautiful dark-themed web interface (stdlib HTTP server)
- **Performance Benchmarks** — Speed, memory, and ciphertext size analysis
- **Small Number Examples** — Hand-traceable demos for academic viva presentations

---

## Getting Started

### Prerequisites

- **Python 3.7+** (no external packages required)

```bash
# Clone the repository
git clone https://github.com/ahmedmesbah0/secure_cloud_portal.git
cd secure_cloud_portal
```

### Running the Full Demo

Runs an automated 10-step demonstration: CA setup → server start → client connection → registration → login → file upload → file listing → file download → key rotation → multi-user simulation → certificate verification.

```bash
python main.py
```

### Interactive CLI Mode

Provides a menu-driven interface for manual interaction:

```bash
python main.py --interactive
```

```
┌─────────────────────────────────┐
│   Secure Cloud Portal - Menu    │
├─────────────────────────────────┤
│  1. Register                    │
│  2. Login                       │
│  3. Upload file                 │
│  4. Download file               │
│  5. List files                  │
│  6. Rotate storage key          │
│  7. View certificates           │
│  8. View database               │
│  0. Exit                        │
└─────────────────────────────────┘
```

### Web GUI Mode

Launches a web-based interface at `http://127.0.0.1:8080`:

```bash
python main.py --gui
```

The GUI features:
- 🔐 Login / Registration screen
- 📁 File upload & download with progress
- 🔏 Certificate viewer with validity badges
- 🗄️ Database inspector (users + files)
- ⚡ Performance benchmark runner
- 📋 Real-time system log viewer
- 🔄 Storage key rotation

---

## Usage Examples

### Individual Algorithm Demos

```bash
# Blowfish encryption demo
python examples/demo_blowfish.py

# ChaCha20 stream cipher demo
python examples/demo_chacha20.py

# ElGamal encryption + signatures demo
python examples/demo_elgamal.py

# Full 10-phase system demo
python examples/demo_full_system.py

# Small number examples (for hand verification / viva)
python examples/demo_small_numbers.py
```

### Using the Crypto Library Directly

```python
from crypto import Blowfish, ChaCha20, ElGamal
import os

# ── Blowfish ──
bf = Blowfish(key=b'mysecretkey12345')
iv = os.urandom(8)
ciphertext = bf.encrypt_cbc(b'Hello, World!', iv)
plaintext = bf.decrypt_cbc(ciphertext, iv)

# ── ChaCha20 ──
key = os.urandom(32)
nonce = os.urandom(12)
cipher = ChaCha20(key, nonce)
encrypted = cipher.encrypt(b'Secret message')
decrypted = ChaCha20(key, nonce).encrypt(encrypted)  # XOR is symmetric

# ── ElGamal ──
eg = ElGamal(bits=512)
pub = eg.get_public_key()

# Encrypt / Decrypt
c1, c2 = eg.encrypt(pub, 42)
message = eg.decrypt(c1, c2)

# Sign / Verify
signature = eg.sign(b'Important document')
valid = ElGamal.verify_signature(pub, b'Important document', signature)
```

---

## Testing

Run the complete test suite:

```bash
python run_all_tests.py
```

The test suite covers:

| Test Module | Tests | Coverage |
|-------------|-------|----------|
| `test_blowfish.py` | 7 | ECB, CBC, different IVs, different keys, empty data, file encryption, large data |
| `test_chacha20.py` | — | Encrypt/decrypt, keystream, large data, nonce sensitivity |
| `test_elgamal.py` | — | Keygen, encrypt/decrypt, sign/verify, key exchange, serialization |
| `test_auth.py` | — | Registration, login, session validation, duplicate users, wrong password |
| `test_ca.py` | — | Certificate issuance, verification, revocation, expiry |
| `test_integration.py` | 1 (full flow) | CA → Server → Client → Register → Login → Upload → Download → Key Rotation → Certificate Verification |

---

## Performance Benchmarks

Run the full benchmark suite:

```bash
python performance/benchmark.py
```

### Benchmarks Included

| Benchmark | Description |
|-----------|-------------|
| **Encryption Speed** | Blowfish CBC vs ChaCha20 at 1KB, 10KB, 100KB |
| **Ciphertext Size** | Expansion comparison (block vs stream cipher) |
| **Memory Usage** | Peak memory via `tracemalloc` for each algorithm |
| **Key Generation** | ElGamal keygen time at 256-bit and 512-bit |
| **Handshake Time** | Full key exchange simulation timing |
| **End-to-End** | Complete system: CA → Server → Client → Upload → Download → Key Rotation |

---

## Security Design

### Password Storage
- Passwords are **never stored in plaintext**
- Each password is hashed with a unique random 16-byte salt: `SHA-256(salt ‖ password)`
- Salt and hash stored in SQLite

### Encryption at Rest
- Files are encrypted with **Blowfish in CBC mode**
- Random 8-byte IV per file (prepended to ciphertext)
- 128-bit storage key stored in `keys/storage_key.bin`
- Key rotation re-encrypts all files with a new key

### Encryption in Transit
- **ElGamal key exchange** establishes a shared secret without transmitting keys
- Shared secret → SHA-256 → **32-byte ChaCha20 session key** + **12-byte nonce**
- All messages are length-prefixed and ChaCha20 encrypted

### Certificate Authority
- CA has its own ElGamal root keypair
- Issues certificates binding subject names to public keys
- Certificates are **digitally signed** by the CA
- Supports certificate **verification** and **revocation**

### Protocol Flow
```
Client                              Server
  │                                    │
  │◄────── Public Key + Certificate ───│  (plaintext)
  │                                    │
  │─── Client Public Key ────────────►│  (plaintext)
  │                                    │
  │  [Both derive shared secret]       │
  │  [shared_secret = other_y^my_x]    │
  │  [session_key = SHA256(secret)]    │
  │                                    │
  │◄══════ ChaCha20 Channel ══════════►│  (encrypted)
  │     register / login / upload      │
  │     download / list / rotate       │
  │                                    │
```

---

## Small Number Examples (For Viva)

The `examples/demo_small_numbers.py` script provides **hand-traceable** examples with tiny parameters:

```bash
python examples/demo_small_numbers.py
```

Includes:
- **Blowfish** — Simplified 2-round Feistel network with visible XOR/swap steps
- **ChaCha20** — Single quarter round with step-by-step ARX operations
- **ElGamal** — Full encryption/decryption/signature with `p=23, g=5, x=6`
- **Diffie-Hellman** — Key exchange with `p=23, g=5, a=6, b=15`

These use small enough numbers that every step can be verified with pen and paper.

---

## License

This project is developed for academic purposes.

---

> **Built from scratch** — No OpenSSL, no PyCryptodome, no cryptography libraries. Every bit is hand-coded.
