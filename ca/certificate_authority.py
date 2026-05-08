"""
Certificate Authority (CA) Simulation.

Simulates a PKI Certificate Authority that can:
- Generate its own root keypair (ElGamal)
- Issue certificates binding identities to public keys
- Sign certificates with the CA's private key
- Verify certificates
- Revoke certificates

Certificate format (JSON-serializable dict):
{
    "serial": int,
    "subject": str,          # e.g., "server" or "alice"
    "public_key": {p, g, y},
    "issued_at": timestamp,
    "expires_at": timestamp,
    "issuer": "SecureCloudCA",
    "signature": (r, s)
}
"""

import json
import time
import hashlib
from crypto.elgamal import ElGamal


class CertificateAuthority:
    """
    Simulated Certificate Authority for the secure cloud portal.
    
    Usage:
        ca = CertificateAuthority(bits=512)
        cert = ca.issue_certificate("server", server_public_key)
        is_valid = ca.verify_certificate(cert)
    """
    
    def __init__(self, bits: int = 512):
        """Initialize CA with its own ElGamal root keypair."""
        print("[CA] Generating root keypair...")
        self.elgamal = ElGamal(bits=bits)
        self.root_public_key = self.elgamal.get_public_key()
        self.serial_counter = 0
        self.issued_certs = {}      # serial -> cert
        self.revoked_serials = set()
        self.name = "SecureCloudCA"
        print(f"[CA] Root keypair generated (p is {bits} bits)")
    
    def _cert_to_signable(self, cert_data: dict) -> bytes:
        """Convert certificate data to bytes for signing (excludes signature)."""
        signable = {
            'serial': cert_data['serial'],
            'subject': cert_data['subject'],
            'public_key_y': cert_data['public_key']['y'],
            'issued_at': cert_data['issued_at'],
            'expires_at': cert_data['expires_at'],
            'issuer': cert_data['issuer'],
        }
        return json.dumps(signable, sort_keys=True).encode()
    
    def issue_certificate(self, subject: str, public_key: dict,
                          validity_days: int = 365) -> dict:
        """
        Issue a signed certificate for a subject.
        
        Args:
            subject: Name/identity (e.g., "server", "alice")
            public_key: The subject's ElGamal public key dict {p, g, y}
            validity_days: How long the cert is valid
        
        Returns:
            Certificate dictionary with CA signature
        """
        self.serial_counter += 1
        now = time.time()
        
        cert = {
            'serial': self.serial_counter,
            'subject': subject,
            'public_key': {
                'p': public_key['p'],
                'g': public_key['g'],
                'y': public_key['y'],
            },
            'issued_at': now,
            'expires_at': now + (validity_days * 86400),
            'issuer': self.name,
        }
        
        # Sign the certificate
        signable = self._cert_to_signable(cert)
        r, s = self.elgamal.sign(signable)
        cert['signature'] = {'r': r, 's': s}
        
        # Store issued certificate
        self.issued_certs[cert['serial']] = cert
        print(f"[CA] Issued certificate #{cert['serial']} for '{subject}'")
        return cert
    
    def verify_certificate(self, cert: dict) -> bool:
        """
        Verify a certificate's authenticity.
        
        Checks:
        1. Signature is valid (signed by this CA)
        2. Certificate has not expired
        3. Certificate has not been revoked
        """
        # Check revocation
        if cert.get('serial') in self.revoked_serials:
            print(f"[CA] Certificate #{cert['serial']} is REVOKED")
            return False
        
        # Check expiration
        if time.time() > cert.get('expires_at', 0):
            print(f"[CA] Certificate #{cert['serial']} has EXPIRED")
            return False
        
        # Verify signature
        signable = self._cert_to_signable(cert)
        sig = cert.get('signature', {})
        signature = (sig.get('r', 0), sig.get('s', 0))
        
        is_valid = ElGamal.verify_signature(
            self.root_public_key, signable, signature
        )
        
        if is_valid:
            print(f"[CA] Certificate #{cert['serial']} for "
                  f"'{cert['subject']}' is VALID")
        else:
            print(f"[CA] Certificate #{cert['serial']} INVALID signature")
        
        return is_valid
    
    def revoke_certificate(self, serial: int):
        """Add a certificate to the revocation list."""
        self.revoked_serials.add(serial)
        print(f"[CA] Certificate #{serial} has been REVOKED")
    
    def get_root_public_key(self) -> dict:
        """Return the CA's root public key for verification."""
        return self.root_public_key
    
    def list_certificates(self) -> list:
        """List all issued certificates."""
        return list(self.issued_certs.values())
