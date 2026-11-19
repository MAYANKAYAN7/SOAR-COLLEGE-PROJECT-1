"""
Cryptographic and security utilities for the SOAR application.
Provides secure password hashing (PBKDF2-HMAC-SHA256 with 600,000 iterations),
standard RFC 7519 JSON Web Token (JWT) handling, and IP sanitization.
"""
import os
import hmac
import hashlib
import ipaddress
import base64
import json
import time
from fastapi import Header, HTTPException, Depends

# OWASP Recommended Iteration Count for PBKDF2-HMAC-SHA256 (2023-2026 standard)
ITERATIONS = 600_000
JWT_SECRET = os.getenv("JWT_SECRET", "soar-incident-control-secure-secret-key-2026-production")


# ── Password Hashing & Verification ──

def hash_password(password: str) -> str:
    """Generate a secure PBKDF2-HMAC-SHA256 salted hash using 600,000 rounds."""
    if not password:
        return ""
    salt = os.urandom(16)
    key = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        ITERATIONS
    )
    return f"pbkdf2:sha256:{ITERATIONS}${salt.hex()}${key.hex()}"


def verify_password(plain_password: str, stored_password: str) -> bool:
    """
    Verify a plain password against stored hash.
    Dynamically extracts iterations from hash prefix to support seamless rotation.
    Supports legacy plaintext comparison with safe constant-time comparison.
    """
    if not plain_password or not stored_password:
        return False

    if stored_password.startswith("pbkdf2:sha256:"):
        try:
            parts = stored_password.split("$")
            if len(parts) != 3:
                return False
            algo_info, salt_hex, key_hex = parts
            iter_count = int(algo_info.split(":")[-1]) if ":" in algo_info else ITERATIONS
            salt = bytes.fromhex(salt_hex)
            expected_key = bytes.fromhex(key_hex)

            calculated_key = hashlib.pbkdf2_hmac(
                "sha256",
                plain_password.encode("utf-8"),
                salt,
                iter_count
            )
            return hmac.compare_digest(calculated_key, expected_key)
        except Exception:
            return False

    # Legacy plaintext check using constant-time comparison
    return hmac.compare_digest(plain_password.encode("utf-8"), stored_password.encode("utf-8"))


# ── RFC 7519 Compliant JSON Web Token (JWT) Handling ──

def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    padding = "=" * (4 - (len(data) % 4))
    return base64.urlsafe_b64decode(data + padding)


def create_jwt_token(payload: dict, expires_in_seconds: int = 86400) -> str:
    """Create a signed HS256 JSON Web Token with expiration."""
    header = {"typ": "JWT", "alg": "HS256"}
    now = int(time.time())
    token_payload = {
        **payload,
        "exp": now + expires_in_seconds,
        "iat": now
    }
    header_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    payload_b64 = _b64url_encode(json.dumps(token_payload, separators=(",", ":")).encode("utf-8"))
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")

    signature = hmac.new(JWT_SECRET.encode("utf-8"), signing_input, hashlib.sha256).digest()
    sig_b64 = _b64url_encode(signature)

    return f"{header_b64}.{payload_b64}.{sig_b64}"


def decode_jwt_token(token: str) -> dict:
    """Validate signature and expiration of an HS256 JWT."""
    if not token or not isinstance(token, str):
        raise ValueError("Invalid token format")
    parts = token.strip().split(".")
    if len(parts) != 3:
        raise ValueError("Malformed JWT structure")

    header_b64, payload_b64, sig_b64 = parts
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    expected_sig = hmac.new(JWT_SECRET.encode("utf-8"), signing_input, hashlib.sha256).digest()

    try:
        provided_sig = _b64url_decode(sig_b64)
    except Exception:
        raise ValueError("Corrupted token signature")

    if not hmac.compare_digest(expected_sig, provided_sig):
        raise ValueError("Invalid token signature")

    try:
        payload_bytes = _b64url_decode(payload_b64)
        payload = json.loads(payload_bytes.decode("utf-8"))
    except Exception:
        raise ValueError("Invalid token payload")

    if "exp" in payload and time.time() > payload["exp"]:
        raise ValueError("Token has expired")

    return payload


# ── FastAPI Authentication Dependencies ──

def get_current_user(authorization: str = Header(None)) -> dict:
    """Dependency that extracts and validates the Bearer JWT from Authorization header."""
    if not authorization:
        raise HTTPException(
            status_code=401,
            detail="Missing Authorization header. Authentication required.",
            headers={"WWW-Authenticate": "Bearer"}
        )
    parts = authorization.strip().split(" ")
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(
            status_code=401,
            detail="Invalid authorization format. Expected 'Bearer <token>'.",
            headers={"WWW-Authenticate": "Bearer"}
        )
    try:
        user_payload = decode_jwt_token(parts[1])
        return user_payload
    except ValueError as e:
        raise HTTPException(
            status_code=401,
            detail=f"Session authentication failed: {str(e)}",
            headers={"WWW-Authenticate": "Bearer"}
        )


def require_role(*allowed_roles):
    """Dependency factory enforcing server-side Role-Based Access Control (RBAC)."""
    def role_checker(user: dict = Depends(get_current_user)):
        user_role = user.get("role", "Analyst")
        if user_role not in allowed_roles:
            raise HTTPException(
                status_code=403,
                detail=f"Forbidden: role '{user_role}' does not have permission for this action."
            )
        return user
    return role_checker


# ── Input Sanitization ──

def is_valid_ip(ip_str: str) -> bool:
    """Validate whether input is a syntactically valid IPv4 or IPv6 address."""
    if not ip_str or not isinstance(ip_str, str):
        return False
    clean_ip = ip_str.strip()
    try:
        ipaddress.ip_address(clean_ip)
        return True
    except ValueError:
        return False
