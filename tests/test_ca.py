"""Unit tests for Certificate Authority."""
import os
import sys
import time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ca.certificate_authority import CertificateAuthority
from crypto.elgamal import ElGamal

BITS = 256


def test_issue_certificate():
    ca = CertificateAuthority(bits=BITS)
    eg = ElGamal(bits=BITS)
    cert = ca.issue_certificate("alice", eg.get_public_key())
    assert cert['subject'] == 'alice'
    assert cert['serial'] == 1
    assert 'signature' in cert
    print("  ✓ Certificate issuance")


def test_verify_valid():
    ca = CertificateAuthority(bits=BITS)
    eg = ElGamal(bits=BITS)
    cert = ca.issue_certificate("server", eg.get_public_key())
    assert ca.verify_certificate(cert) == True
    print("  ✓ Valid certificate verification")


def test_verify_tampered():
    ca = CertificateAuthority(bits=BITS)
    eg = ElGamal(bits=BITS)
    cert = ca.issue_certificate("server", eg.get_public_key())
    cert['subject'] = 'attacker'  # Tamper with subject
    assert ca.verify_certificate(cert) == False
    print("  ✓ Tampered certificate rejected")


def test_revocation():
    ca = CertificateAuthority(bits=BITS)
    eg = ElGamal(bits=BITS)
    cert = ca.issue_certificate("user1", eg.get_public_key())
    ca.revoke_certificate(cert['serial'])
    assert ca.verify_certificate(cert) == False
    print("  ✓ Revoked certificate rejected")


def test_multiple_certs():
    ca = CertificateAuthority(bits=BITS)
    for i in range(3):
        eg = ElGamal(bits=BITS)
        cert = ca.issue_certificate(f"user{i}", eg.get_public_key())
        assert cert['serial'] == i + 1
    assert len(ca.list_certificates()) == 3
    print("  ✓ Multiple certificates")


def test_root_public_key():
    ca = CertificateAuthority(bits=BITS)
    rpk = ca.get_root_public_key()
    assert 'p' in rpk and 'g' in rpk and 'y' in rpk
    print("  ✓ Root public key retrieval")


def run_all():
    print("\n[TEST] Certificate Authority Tests")
    print("-" * 30)
    test_issue_certificate()
    test_verify_valid()
    test_verify_tampered()
    test_revocation()
    test_multiple_certs()
    test_root_public_key()
    print("All CA tests PASSED ✓\n")


if __name__ == '__main__':
    run_all()
