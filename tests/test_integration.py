"""Integration test - Full system flow."""
import os
import sys
import time
import threading
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ca.certificate_authority import CertificateAuthority
from server.server import SecureServer
from client.client import SecureClient


def test_full_flow():
    """Test complete system: CA -> Server -> Client -> Upload -> Download."""
    BITS = 256

    # Clean
    import shutil
    for d in ['data', 'keys']:
        if os.path.exists(d):
            shutil.rmtree(d)

    # Setup CA
    ca = CertificateAuthority(bits=BITS)

    # Start server
    server = SecureServer(host='127.0.0.1', port=5558, ca=ca, elgamal_bits=BITS)
    server_thread = threading.Thread(target=server.start, daemon=True)
    server_thread.start()
    time.sleep(1)

    try:
        # Client connects
        client = SecureClient(host='127.0.0.1', port=5558, ca=ca, elgamal_bits=BITS)
        assert client.connect(), "Connection failed"
        print("  ✓ Client connected and handshake complete")

        # Register and login
        assert client.register("testuser", "testpass")
        assert client.login("testuser", "testpass")
        print("  ✓ Registration and login")

        # Upload file
        os.makedirs('data', exist_ok=True)
        test_data = "Integration test content: 12345"
        with open('data/integ_test.txt', 'w') as f:
            f.write(test_data)
        assert client.upload_file('data/integ_test.txt')
        print("  ✓ File upload")

        # List files
        files = client.list_files()
        assert 'integ_test.txt' in files
        print("  ✓ File listing")

        # Download file
        assert client.download_file('integ_test.txt', 'data/integ_downloaded.txt')
        with open('data/integ_downloaded.txt', 'r') as f:
            result = f.read()
        assert result == test_data, f"Content mismatch: {result}"
        print("  ✓ File download and integrity check")

        # Key rotation
        assert client.rotate_key()
        assert client.download_file('integ_test.txt', 'data/integ_rotated.txt')
        with open('data/integ_rotated.txt', 'r') as f:
            rotated = f.read()
        assert rotated == test_data
        print("  ✓ Key rotation with file integrity")

        # Certificate verification
        for cert in ca.list_certificates():
            assert ca.verify_certificate(cert)
        print("  ✓ All certificates valid")

        client.disconnect()
    finally:
        server.stop()

    print("\n  Integration test PASSED ✓")


def run_all():
    print("\n[TEST] Integration Test")
    print("-" * 30)
    test_full_flow()
    print()


if __name__ == '__main__':
    run_all()
