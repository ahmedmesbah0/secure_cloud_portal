"""Unit tests for Authentication Manager."""
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from auth.auth_manager import AuthManager


def setup():
    """Create fresh auth manager for testing."""
    db_path = 'data/test_users.json'
    os.makedirs('data', exist_ok=True)
    if os.path.exists(db_path):
        os.remove(db_path)
    return AuthManager(db_path)


def test_register():
    auth = setup()
    assert auth.register('alice', 'pass123') == True
    assert auth.user_exists('alice')
    print("  ✓ User registration")


def test_register_duplicate():
    auth = setup()
    auth.register('alice', 'pass123')
    assert auth.register('alice', 'other') == False
    print("  ✓ Duplicate registration rejected")


def test_login_success():
    auth = setup()
    auth.register('alice', 'pass123')
    token = auth.login('alice', 'pass123')
    assert token is not None
    print("  ✓ Login success")


def test_login_wrong_password():
    auth = setup()
    auth.register('alice', 'pass123')
    token = auth.login('alice', 'wrongpass')
    assert token is None
    print("  ✓ Login with wrong password rejected")


def test_login_nonexistent():
    auth = setup()
    token = auth.login('nobody', 'pass')
    assert token is None
    print("  ✓ Login with nonexistent user rejected")


def test_session_validation():
    auth = setup()
    auth.register('bob', 'bobpass')
    token = auth.login('bob', 'bobpass')
    user = auth.validate_session(token)
    assert user == 'bob'
    print("  ✓ Session validation")


def test_session_invalid_token():
    auth = setup()
    assert auth.validate_session('fake_token') is None
    print("  ✓ Invalid token rejected")


def test_logout():
    auth = setup()
    auth.register('charlie', 'cpass')
    token = auth.login('charlie', 'cpass')
    auth.logout(token)
    assert auth.validate_session(token) is None
    print("  ✓ Logout invalidates session")


def test_password_hashing():
    """Verify passwords are stored as hashes, not plaintext."""
    auth = setup()
    auth.register('dave', 'mypassword')
    user_data = auth.users['dave']
    assert 'password_hash' in user_data
    assert 'salt' in user_data
    assert user_data['password_hash'] != 'mypassword'
    assert len(user_data['salt']) == 32  # 16 bytes hex = 32 chars
    print("  ✓ Passwords stored as salted hashes")


def test_list_users():
    auth = setup()
    auth.register('alice', 'a')
    auth.register('bob', 'b')
    users = auth.list_users()
    assert 'alice' in users and 'bob' in users
    print("  ✓ List users")


def cleanup():
    if os.path.exists('data/test_users.json'):
        os.remove('data/test_users.json')


def run_all():
    print("\n[TEST] Auth Manager Tests")
    print("-" * 30)
    test_register()
    test_register_duplicate()
    test_login_success()
    test_login_wrong_password()
    test_login_nonexistent()
    test_session_validation()
    test_session_invalid_token()
    test_logout()
    test_password_hashing()
    test_list_users()
    cleanup()
    print("All Auth tests PASSED ✓\n")


if __name__ == '__main__':
    run_all()
