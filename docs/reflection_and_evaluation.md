# Project Reflection and Self-Evaluation

## 1. What I Used in This Project
I built this project entirely in Python using only standard libraries like `socket`, `json`, `hashlib`, `random`, `time`, and `os`. My goal was to strictly avoid external cryptographic packages (like `cryptography` or `PyCryptodome`) to really understand how the math and algorithms work under the hood.

For the cryptography side, I implemented three main algorithms from scratch:
- **Blowfish (CBC mode):** Used for encrypting files stored on the server (encryption at rest). I chose this because building a Feistel network is a classic learning exercise, and its 64-bit blocks with variable-length keys felt like a good fit for file storage.
- **ChaCha20:** Used to encrypt the actual socket communication (encryption in transit). I wanted a stream cipher here because it doesn't require block padding and is extremely fast, making the client-server chat feel responsive without lag.
- **ElGamal:** Handled key exchange and digital signatures. The Diffie-Hellman style key exchange was perfect for establishing the ChaCha20 session keys without ever sending them over the network.

The system is split into three main components: a Client, a Server, and a simulated Certificate Authority (CA). The CA was crucial because I needed a way to prove that the server the client connects to is actually the real server (preventing man-in-the-middle attacks). Every single cryptographic function, from the Miller-Rabin primality tests to the ChaCha quarter rounds, was written completely from scratch.

---

## 2. What Was the Most Difficult Part
Without a doubt, the ElGamal implementation and the underlying number theory was the toughest part.

Getting the modular exponentiation and prime generation to work efficiently was a headache. At first, my prime generation was taking way too long, or generating numbers that weren't "safe primes," which meant the generator $g$ wouldn't cover the full mathematical group properly. I had to go back and really study the math behind finding primitive roots and implementing the Extended Euclidean Algorithm for modular inverses (which is needed for the ElGamal signature generation and decryption).

Debugging this was tricky because a math error just results in gibberish decryption or failed signatures, with no clear indication of *which* step went wrong. I solved this by writing a small-number test script (`demo_small_numbers.py`) using tiny primes like 23 so I could trace the calculations by hand on paper. Once the small numbers worked, scaling it up to 256 or 512 bits worked perfectly.

---

## 3. What I Learned
This project was a massive learning experience. Specifically:
- **Symmetric vs. Asymmetric:** I finally grasped *why* we use both in modern systems. Asymmetric (ElGamal) is mathematically elegant but incredibly slow. Using it just to securely exchange a symmetric key (ChaCha20) which then handles the heavy lifting is a concept that makes complete practical sense to me now.
- **Key Management is Hard:** Writing the encryption algorithm is only half the battle. Storing the keys, rotating them, deriving session keys, and making sure the client and server agree on them without leaking them was much more complex than the actual XOR operations.
- **Protocol Design:** I learned how to structure a basic secure protocol. Doing the CA handshake first, verifying the signature, then doing the DH key exchange, and *then* starting the encrypted channel mirrors how real TLS works, just on a simpler scale.
- **Performance Tradeoffs:** Using 256/512-bit primes instead of 2048-bit for ElGamal was a deliberate tradeoff to keep the demo running smoothly. It highlighted that security often directly competes with performance and user experience.

---

## 4. Limitations of the Project
While it works well for a coursework project, it's definitely not production-ready:
- **Custom Crypto is Risky:** Implementing crypto from scratch is famously dangerous. My code hasn't been audited for side-channel attacks (like timing attacks during modular exponentiation).
- **Key Sizes:** I defaulted to smaller primes for ElGamal to make the demo run faster. Real-world systems use 2048+ bits, but calculating that in pure Python takes too long.
- **Replay Attacks:** While I used nonces in ChaCha20, my socket protocol doesn't have a strict sequence numbering system to prevent sophisticated replay or message reordering attacks over the network.
- **Basic CA:** The CA is simulated and lives locally. In a real system, certificate validation involves checking complex trust chains (X.509) and online revocation lists (OCSP).

---

## 5. Self-Evaluation / Rating

**Technical implementation: 9/10**
I successfully coded three complex algorithms (Blowfish, ChaCha20, ElGamal) entirely from scratch without libraries. They work correctly across file boundaries and live socket streams.

**Security design: 8/10**
The architecture is solid (defense in depth with at-rest and in-transit encryption, salted passwords, CA validation). It loses a point only because of the inherent risks of custom implementations and the lack of robust network replay protection.

**Code quality: 8/10**
The code is modular, separated by concern (auth, crypto, ca, server, client), and heavily commented. I included testing suites which helps, but some of the raw TCP socket handling could be more robust against unexpected network drops.

**System integration: 9/10**
The way the CA, client, and server interact is seamless. The automatic derivation of ChaCha20 session keys from the ElGamal shared secret worked better than I initially expected.

**Overall completeness: 9/10**
It meets all the coursework requirements, includes full unit/integration testing, performance benchmarks, and a working demo that simulates the entire lifecycle of a user interacting with the portal.

**Overall final score: 8.6/10**
I'm very proud of this project. It goes beyond just writing a cipher by building a complete ecosystem around it. It proved to be a challenging but highly rewarding exercise in applied cryptography.

---

## 6. Future Improvements
If I had more time or were to take this further, I would focus on:
- **HMAC for Integrity:** Adding a Message Authentication Code (like HMAC-SHA256) to the ChaCha20 stream to ensure the ciphertext hasn't been tampered with (Authenticated Encryption).
- **Better Socket Protocol:** Upgrading the raw TCP sockets to handle dropped packets gracefully and prevent message reordering.
- **Graphical Interface:** Building a simple Tkinter or PyQt UI so users don't have to use the terminal.
- **Post-Quantum Considerations:** It would be interesting to research and perhaps implement a toy version of a lattice-based key exchange algorithm, knowing that algorithms like ElGamal are theoretically vulnerable to Shor's algorithm on quantum computers.
