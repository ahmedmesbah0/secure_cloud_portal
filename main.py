"""
Secure Cloud Document Portal - Main Entry Point

This script demonstrates the complete system:
1. CA setup and certificate issuance
2. Server startup with encrypted file storage
3. Client connection with secure handshake
4. User registration and login
5. Encrypted file upload/download
6. Key rotation
7. Multi-user simulation

Run: python main.py
"""

import os
import sys
import time
import threading

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def clean_data():
    """Remove previous run data for a clean demo (preserves the database)."""
    import shutil
    for d in ['keys']:
        if os.path.exists(d):
            shutil.rmtree(d)
    # Clean encrypted files but keep the database
    data_dir = 'data'
    if os.path.exists(data_dir):
        for item in os.listdir(data_dir):
            item_path = os.path.join(data_dir, item)
            if item.endswith('.db'):
                continue  # preserve the SQLite database
            if os.path.isdir(item_path):
                shutil.rmtree(item_path)
            else:
                os.remove(item_path)
    print("Cleaned previous data (database preserved).\n")


def run_full_demo():
    """Run the complete system demonstration."""
    from ca.certificate_authority import CertificateAuthority
    from server.server import SecureServer
    from client.client import SecureClient

    print("=" * 60)
    print("  SECURE CLOUD DOCUMENT PORTAL - FULL DEMO")
    print("=" * 60)
    print()

    # Use smaller keys for demo speed
    BITS = 256

    # ─── Step 1: Certificate Authority ───
    print("─" * 40)
    print("STEP 1: Setting up Certificate Authority")
    print("─" * 40)
    ca = CertificateAuthority(bits=BITS)
    print()

    # ─── Step 2: Start Server ───
    print("─" * 40)
    print("STEP 2: Starting Secure Server")
    print("─" * 40)
    server = SecureServer(
        host='127.0.0.1', port=5556, ca=ca, elgamal_bits=BITS
    )
    server_thread = threading.Thread(target=server.start, daemon=True)
    server_thread.start()
    time.sleep(1)  # Wait for server to start
    print()

    # ─── Step 3: Client Connects ───
    print("─" * 40)
    print("STEP 3: Client Connection & Handshake")
    print("─" * 40)
    client = SecureClient(
        host='127.0.0.1', port=5556, ca=ca, elgamal_bits=BITS
    )
    if not client.connect():
        print("Connection failed!")
        server.stop()
        return
    print()

    # ─── Step 4: Registration & Login ───
    print("─" * 40)
    print("STEP 4: User Registration & Login")
    print("─" * 40)
    client.register("alice", "securepass123")
    client.login("alice", "securepass123")
    print()

    # ─── Step 5: File Upload ───
    print("─" * 40)
    print("STEP 5: Encrypted File Upload")
    print("─" * 40)

    # Create a test file
    test_content = "This is a secret document.\nIt contains confidential data.\nOnly authorized users can read this."
    os.makedirs('data', exist_ok=True)
    with open('data/test_document.txt', 'w') as f:
        f.write(test_content)
    print(f"Original file content:\n{test_content}\n")

    client.upload_file('data/test_document.txt')
    print()

    # ─── Step 6: File Listing ───
    print("─" * 40)
    print("STEP 6: List Files on Server")
    print("─" * 40)
    client.list_files()
    print()

    # ─── Step 7: File Download ───
    print("─" * 40)
    print("STEP 7: Encrypted File Download")
    print("─" * 40)
    client.download_file('test_document.txt', 'data/retrieved_document.txt')

    with open('data/retrieved_document.txt', 'r') as f:
        retrieved = f.read()
    print(f"Retrieved content:\n{retrieved}")
    assert retrieved == test_content, "Content mismatch!"
    print("✓ File integrity verified!\n")

    # ─── Step 8: Key Rotation ───
    print("─" * 40)
    print("STEP 8: Storage Key Rotation")
    print("─" * 40)
    client.rotate_key()

    # Verify file still readable after rotation
    client.download_file('test_document.txt', 'data/after_rotation.txt')
    with open('data/after_rotation.txt', 'r') as f:
        rotated = f.read()
    assert rotated == test_content, "Content mismatch after rotation!"
    print("✓ File still readable after key rotation!\n")

    # ─── Step 9: Multi-user simulation ───
    print("─" * 40)
    print("STEP 9: Multi-User Simulation")
    print("─" * 40)

    # Second client (Bob)
    client2 = SecureClient(
        host='127.0.0.1', port=5556, ca=ca, elgamal_bits=BITS
    )
    client2.connect()
    client2.register("bob", "bobpass456")
    client2.login("bob", "bobpass456")

    with open('data/bob_file.txt', 'w') as f:
        f.write("Bob's private data")
    client2.upload_file('data/bob_file.txt')
    client2.list_files()
    client2.disconnect()
    print()

    # ─── Step 10: Certificate Verification ───
    print("─" * 40)
    print("STEP 10: Certificate Verification")
    print("─" * 40)
    certs = ca.list_certificates()
    for cert in certs:
        ca.verify_certificate(cert)
    print()

    # ─── Cleanup ───
    client.disconnect()
    server.stop()

    print("=" * 60)
    print("  DEMO COMPLETE - All features demonstrated!")
    print("=" * 60)


def run_interactive():
    """Run interactive menu mode."""
    from ca.certificate_authority import CertificateAuthority
    from server.server import SecureServer
    from client.client import SecureClient

    BITS = 256
    print("Initializing system (this may take a moment)...")
    ca = CertificateAuthority(bits=BITS)
    server = SecureServer(host='127.0.0.1', port=5557, ca=ca, elgamal_bits=BITS)
    server_thread = threading.Thread(target=server.start, daemon=True)
    server_thread.start()
    time.sleep(1)

    client = SecureClient(host='127.0.0.1', port=5557, ca=ca, elgamal_bits=BITS)
    client.connect()

    while True:
        print("\n┌─────────────────────────────────┐")
        print("│   Secure Cloud Portal - Menu    │")
        print("├─────────────────────────────────┤")
        print("│  1. Register                    │")
        print("│  2. Login                       │")
        print("│  3. Upload file                 │")
        print("│  4. Download file               │")
        print("│  5. List files                  │")
        print("│  6. Rotate storage key          │")
        print("│  7. View certificates           │")
        print("│  8. View database               │")
        print("│  0. Exit                        │")
        print("└─────────────────────────────────┘")

        choice = input("Choice: ").strip()

        if choice == '1':
            u = input("Username: ").strip()
            p = input("Password: ").strip()
            client.register(u, p)

        elif choice == '2':
            u = input("Username: ").strip()
            p = input("Password: ").strip()
            client.login(u, p)

        elif choice == '3':
            path = input("File path: ").strip()
            client.upload_file(path)

        elif choice == '4':
            name = input("Filename: ").strip()
            save = input("Save as (enter for default): ").strip()
            client.download_file(name, save or None)

        elif choice == '5':
            client.list_files()

        elif choice == '6':
            client.rotate_key()

        elif choice == '7':
            certs = ca.list_certificates()
            for c in certs:
                print(f"  #{c['serial']} - {c['subject']} "
                      f"(valid: {ca.verify_certificate(c)})")

        elif choice == '0':
            client.disconnect()
            server.stop()
            # Close database connection
            server.auth.close()
            print("Goodbye!")
            break

        elif choice == '8':
            data = server.auth.get_all_data()
            print("\n┌─── Database Contents ───────────────┐")
            print("│ USERS:")
            if data['users']:
                for u in data['users']:
                    import datetime
                    created = datetime.datetime.fromtimestamp(
                        u['created_at']
                    ).strftime('%Y-%m-%d %H:%M:%S')
                    print(f"│   • {u['username']}  (created: {created})")
            else:
                print("│   (none)")
            print("│")
            print("│ FILES:")
            if data['files']:
                for f in data['files']:
                    import datetime
                    uploaded = datetime.datetime.fromtimestamp(
                        f['uploaded_at']
                    ).strftime('%Y-%m-%d %H:%M:%S')
                    print(f"│   • {f['filename']}  owner={f['owner']}  "
                          f"size={f['file_size']}B  uploaded={uploaded}")
            else:
                print("│   (none)")
            print("└─────────────────────────────────────┘")


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--gui':
        from gui_server import main as gui_main
        gui_main()
    elif len(sys.argv) > 1 and sys.argv[1] == '--interactive':
        clean_data()
        run_interactive()
    else:
        clean_data()
        run_full_demo()
