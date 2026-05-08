"""Run all tests for the Secure Cloud Portal."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from tests.test_blowfish import run_all as test_blowfish
from tests.test_chacha20 import run_all as test_chacha20
from tests.test_elgamal import run_all as test_elgamal
from tests.test_auth import run_all as test_auth
from tests.test_ca import run_all as test_ca
from tests.test_integration import run_all as test_integration

if __name__ == '__main__':
    print("=" * 50)
    print("  SECURE CLOUD PORTAL - TEST SUITE")
    print("=" * 50)

    test_blowfish()
    test_chacha20()
    test_elgamal()
    test_auth()
    test_ca()
    test_integration()

    print("=" * 50)
    print("  ALL TESTS PASSED ✓")
    print("=" * 50)
