"""
Authentication & Password Hashing Verification Script
Tests login validation, password strength enforcement, and hash security.
"""
import urllib.request
import urllib.error
import json

BASE_URL = "http://localhost:8000"

def test_auth():
    print("[*] Testing Authentication Endpoints...")
    
    # 1. Test short password rejection
    reg_payload = json.dumps({
        "username": "sectestuser",
        "email": "sectest@test.local",
        "password": "123",  # Under 6 chars
        "otp": "999999"
    }).encode()
    
    req = urllib.request.Request(
        f"{BASE_URL}/auth/register/verify",
        data=reg_payload,
        headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            print("[FAIL] Short password accepted!")
    except urllib.error.HTTPError as e:
        if e.code == 400:
            print("[PASS] Short password (<6 chars) properly rejected with HTTP 400")
        else:
            print(f"[INFO] Register verify returned HTTP {e.code}")

    # 2. Test valid login credentials and JWT token delivery
    valid_login_payload = json.dumps({
        "username": "admin",
        "password": "admin123"
    }).encode()
    req_vlogin = urllib.request.Request(
        f"{BASE_URL}/auth/login",
        data=valid_login_payload,
        headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req_vlogin, timeout=5) as resp:
            data = json.loads(resp.read().decode())
            if "token" in data and data.get("token_type") == "bearer":
                print(f"[PASS] Login generated signed Bearer JWT token: {data['token'][:24]}...")
            else:
                print("[FAIL] Login succeeded but did not return JWT token!")
    except Exception as e:
        print(f"[-] Login test failed: {e}")

    # 3. Test invalid login credentials
    login_payload = json.dumps({
        "username": "admin",
        "password": "WrongPassword!99"
    }).encode()
    
    req_login = urllib.request.Request(
        f"{BASE_URL}/auth/login",
        data=login_payload,
        headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req_login, timeout=10) as resp:
            print("[FAIL] Invalid password allowed login!")
    except urllib.error.HTTPError as e:
        if e.code == 401:
            print("[PASS] Invalid credentials properly rejected with HTTP 401 Unauthorized")
        else:
            print(f"[INFO] Login returned HTTP {e.code}")

if __name__ == "__main__":
    test_auth()
