"""
Full system demonstration - simulates the entire portal in one script.

Shows: CA → Certificates → Handshake → Auth → Upload → Download → Key Rotation
All without needing to start separate server/client processes.
"""
import sys, os, time, threading
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import shutil
from ca.certificate_authority import CertificateAuthority
from server.server import SecureServer
from client.client import SecureClient

# Clean previous data
for d in ['data', 'keys']:
    if os.path.exists(d):
        shutil.rmtree(d)

BITS = 256
PORT = 5559

print("╔══════════════════════════════════════════════╗")
print("║  SECURE CLOUD PORTAL - FULL SYSTEM DEMO     ║")
print("╚══════════════════════════════════════════════╝\n")

# Phase 1: Certificate Authority
print("▶ PHASE 1: Certificate Authority Setup")
ca = CertificateAuthority(bits=BITS)
print()

# Phase 2: Server
print("▶ PHASE 2: Server Initialization")
server = SecureServer(host='127.0.0.1', port=PORT, ca=ca, elgamal_bits=BITS)
t = threading.Thread(target=server.start, daemon=True)
t.start()
time.sleep(1)
print()

# Phase 3: Client 1 (Alice)
print("▶ PHASE 3: Alice Connects")
alice = SecureClient(host='127.0.0.1', port=PORT, ca=ca, elgamal_bits=BITS)
alice.connect()
print()

# Phase 4: Alice registers and logs in
print("▶ PHASE 4: Alice Authentication")
alice.register("alice", "alice_secure_password")
alice.login("alice", "alice_secure_password")
print()

# Phase 5: Alice uploads a document
print("▶ PHASE 5: Document Upload")
os.makedirs('data', exist_ok=True)
secret = "=== QUARTERLY REPORT ===\nRevenue: $2.5M\nProfit: $800K\nClassification: TOP SECRET"
with open('data/quarterly_report.txt', 'w') as f:
    f.write(secret)
print(f"Original document:\n{secret}\n")
alice.upload_file('data/quarterly_report.txt')
print()

# Phase 6: Show encrypted file on disk
print("▶ PHASE 6: Encrypted Storage")
enc_path = 'data/files/alice/quarterly_report.txt.enc'
if os.path.exists(enc_path):
    with open(enc_path, 'rb') as f:
        enc = f.read()
    print(f"Encrypted file on disk ({len(enc)} bytes):")
    print(f"  {enc[:40].hex()}...")
    print("  (unreadable without the key)")
print()

# Phase 7: Alice downloads
print("▶ PHASE 7: Document Download")
alice.download_file('quarterly_report.txt', 'data/downloaded_report.txt')
with open('data/downloaded_report.txt', 'r') as f:
    dl = f.read()
print(f"Downloaded content:\n{dl}")
assert dl == secret
print("✓ Content integrity verified!\n")

# Phase 8: Key rotation
print("▶ PHASE 8: Storage Key Rotation")
alice.rotate_key()
alice.download_file('quarterly_report.txt', 'data/rotated_report.txt')
with open('data/rotated_report.txt', 'r') as f:
    r = f.read()
assert r == secret
print("✓ Files accessible after key rotation!\n")

# Phase 9: Bob connects (multi-user)
print("▶ PHASE 9: Multi-User - Bob")
bob = SecureClient(host='127.0.0.1', port=PORT, ca=ca, elgamal_bits=BITS)
bob.connect()
bob.register("bob", "bob_password")
bob.login("bob", "bob_password")
with open('data/bob_notes.txt', 'w') as f:
    f.write("Bob's private notes - do not share!")
bob.upload_file('data/bob_notes.txt')
bob.list_files()
bob.disconnect()
print()

# Phase 10: Certificate summary
print("▶ PHASE 10: Certificate Summary")
print(f"Certificates issued: {len(ca.list_certificates())}")
for cert in ca.list_certificates():
    status = "VALID" if ca.verify_certificate(cert) else "INVALID"
    # (verify_certificate already prints, but we get the bool)
print()

alice.disconnect()
server.stop()

print("╔══════════════════════════════════════════════╗")
print("║  ALL PHASES COMPLETE - SYSTEM WORKING ✓     ║")
print("╚══════════════════════════════════════════════╝")
