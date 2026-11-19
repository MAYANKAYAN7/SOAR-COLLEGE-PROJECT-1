import os
import time
import random
import smtplib
from email.message import EmailMessage
from datetime import datetime
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, EmailStr
from app.core.config import settings
from app.core.logger import logger
from app.core.security import (
    hash_password, verify_password,
    create_jwt_token, get_current_user, require_role
)
from app.core.database import (
    db_find_user, db_save_user, db_update_user_password,
    db_save_otp, db_verify_otp, is_mongo_connected
)

router = APIRouter(
    prefix="/auth",
    tags=["Authentication"]
)

# In-memory users for quick local fallback
users = {
    "analyst": {
        "password": "analyst123",
        "email": "analyst@soar.local",
        "role": "Analyst",
        "created_at": "2026-01-01T00:00:00"
    },
    "senior": {
        "password": "senior123",
        "email": "senior@soar.local",
        "role": "Senior Analyst",
        "created_at": "2026-01-01T00:00:00"
    },
    "admin": {
        "password": "admin123",
        "email": "admin@soar.local",
        "role": "Admin",
        "created_at": "2026-01-01T00:00:00"
    }
}

# Temporary OTP storage & security tracking
in_memory_otps = {}
otp_request_cooldown = {}   # email -> float (last request timestamp)
otp_request_counts = {}     # email -> list of float timestamps in last 10m
otp_failed_attempts = {}    # email -> int (failed attempt count)
MAX_OTP_ATTEMPTS = 5


# ── Schemas ──

class LoginRequest(BaseModel):
    username: str
    password: str


class OTPRequest(BaseModel):
    email: str
    username: str


class RegisterVerifyRequest(BaseModel):
    username: str
    email: str
    password: str
    role: str = "Analyst"
    otp: str


class ChangePasswordRequest(BaseModel):
    username: str
    current_password: str
    new_password: str


def send_otp_email(to_email: str, otp_code: str) -> bool:
    """Send real OTP email via SMTP (SSL/TLS). Raises HTTPException if not configured or failed."""
    smtp_host = settings.SMTP_HOST or os.getenv("SMTP_HOST", "smtp.gmail.com")
    smtp_user = settings.SMTP_USER or os.getenv("SMTP_USER")
    smtp_pass = settings.SMTP_PASS or os.getenv("SMTP_PASS")
    smtp_from = settings.SMTP_FROM or os.getenv("SMTP_FROM", smtp_user or "noreply@soar-engine.local")

    if not smtp_user or not smtp_pass:
        logger.error("SMTP credentials (SMTP_USER / SMTP_PASS) not configured in .env.")
        raise HTTPException(
            status_code=503,
            detail="Mail server not configured. Please add SMTP_USER and SMTP_PASS (e.g. Gmail App Password) to Mayank/backend/.env to send real verification emails."
        )

    msg = EmailMessage()
    msg["Subject"] = f"Your SOAR Verification Code: {otp_code}"
    msg["From"] = f'"SOAR Incident Engine" <{smtp_from}>'
    msg["To"] = to_email
    msg["Reply-To"] = smtp_from

    plain_text = f"""Hello,

Your verification code for registering your account with the SOAR Incident Containment Engine is:

    {otp_code}

This security code expires in 10 minutes. If you did not request this code, please ignore this email.

Best regards,
Security Operations Team
"""
    html_content = f"""<!DOCTYPE html>
<html>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #f1f5f9; padding: 24px; margin: 0;">
  <div style="max-width: 480px; margin: 0 auto; background: #ffffff; border-radius: 16px; padding: 32px; border: 1px solid #e2e8f0; text-align: center; box-shadow: 0 4px 12px rgba(0,0,0,0.05);">
    <div style="display: inline-block; width: 44px; height: 44px; background: #0f172a; border-radius: 12px; color: #ffffff; line-height: 44px; font-size: 20px; margin-bottom: 14px;">🛡️</div>
    <h2 style="color: #0f172a; margin: 0 0 8px 0; font-size: 22px; font-weight: 800;">SOAR Incident Control</h2>
    <p style="color: #64748b; font-size: 14px; margin: 0 0 24px 0;">Use the single-use verification code below to complete your registration:</p>
    <div style="font-size: 34px; font-weight: 800; letter-spacing: 8px; color: #1e293b; background: #f8fafc; border: 2px dashed #cbd5e1; padding: 14px 24px; border-radius: 12px; display: inline-block; margin-bottom: 24px; font-family: monospace;">
      {otp_code}
    </div>
    <p style="color: #94a3b8; font-size: 12px; margin: 0;">This code expires in 10 minutes. If you did not request this, please disregard this email.</p>
  </div>
</body>
</html>"""

    msg.set_content(plain_text)
    msg.add_alternative(html_content, subtype="html")

    # Try Port 465 (Direct SSL) first for maximum reliability, then fallback to Port 587 (STARTTLS)
    last_err = None
    for attempt in range(2):
        try:
            with smtplib.SMTP_SSL(smtp_host, 465, timeout=15) as server:
                server.login(smtp_user, smtp_pass)
                server.send_message(msg)
            logger.info(f"Verification OTP email dispatched successfully to {to_email} via Port 465 SSL")
            return True
        except Exception as e:
            last_err = e
            try:
                with smtplib.SMTP(smtp_host, 587, timeout=15) as server:
                    server.starttls()
                    server.login(smtp_user, smtp_pass)
                    server.send_message(msg)
                logger.info(f"Verification OTP email dispatched successfully to {to_email} via Port 587 STARTTLS")
                return True
            except Exception as e2:
                last_err = e2

    logger.error(f"Failed to send email to {to_email}: {last_err}")
    raise HTTPException(
        status_code=502,
        detail=f"Could not send email to {to_email} via SMTP: {str(last_err)}"
    )


# ── Routes ──

@router.post("/login")
async def login(request: LoginRequest):
    uname = request.username.strip()
    
    # 1. Check MongoDB Atlas if available
    db_user = await db_find_user(uname)
    if db_user:
        stored_pwd = db_user.get("password", "")
        if verify_password(request.password, stored_pwd):
            # Auto-upgrade plaintext to PBKDF2 hash (600,000 rounds)
            if not stored_pwd.startswith("pbkdf2:"):
                upgraded_hash = hash_password(request.password)
                await db_update_user_password(uname, upgraded_hash)
            role = db_user.get("role", "Analyst")
            email = db_user.get("email", f"{uname}@soar.local")
            token = create_jwt_token({"sub": uname, "role": role, "email": email})
            return {
                "message": "Login successful",
                "token": token,
                "token_type": "bearer",
                "username": db_user.get("username", uname),
                "role": role,
                "email": email
            }
        else:
            raise HTTPException(status_code=401, detail="Invalid username or password")

    # 2. Check in-memory store
    user = users.get(uname)
    if not user or not verify_password(request.password, user.get("password", "")):
        raise HTTPException(status_code=401, detail="Invalid username or password")

    role = user["role"]
    email = user.get("email", f"{uname}@soar.local")
    token = create_jwt_token({"sub": uname, "role": role, "email": email})
    return {
        "message": "Login successful",
        "token": token,
        "token_type": "bearer",
        "username": uname,
        "role": role,
        "email": email
    }


@router.post("/register/request-otp")
async def request_otp(req: OTPRequest):
    email = req.email.strip().lower()
    username = req.username.strip().lower()

    if not email or "@" not in email:
        raise HTTPException(status_code=400, detail="Please enter a valid email address.")
    if len(username) < 3:
        raise HTTPException(status_code=400, detail="Username must be at least 3 characters.")

    # ── Security Rate Limiting & Cooldown (Fast 10s Demo-Friendly Cooldown) ──
    now = time.time()
    last_req = otp_request_cooldown.get(email, 0)
    cooldown_seconds = 10  # 10s cooldown between rapid requests
    if now - last_req < cooldown_seconds:
        remaining = int(cooldown_seconds - (now - last_req))
        raise HTTPException(status_code=429, detail=f"Please wait {remaining} seconds before requesting another verification code.")

    # Max 10 requests per 10 minutes (generous for testing / demonstration)
    window = [t for t in otp_request_counts.get(email, []) if now - t < 600]
    if len(window) >= 10:
        raise HTTPException(status_code=429, detail="Verification request limit reached (max 10 per 10 minutes). Please wait a few minutes.")
    window.append(now)
    otp_request_counts[email] = window
    otp_request_cooldown[email] = now

    # Check if user already exists in MongoDB or memory
    existing_mongo = await db_find_user(username)
    if existing_mongo or username in users:
        raise HTTPException(status_code=400, detail=f"Username '{username}' is already taken.")

    # Generate 6-digit OTP
    otp_code = f"{random.randint(100000, 999999)}"
    expires_at = time.time() + 600  # 10 minutes

    # Reset failed attempts for new OTP cycle
    otp_failed_attempts[email] = 0

    # Send email first - if this fails, we do NOT proceed
    send_otp_email(email, otp_code)

    # Save to memory and MongoDB
    in_memory_otps[email] = {"otp": otp_code, "expires_at": expires_at}
    await db_save_otp(email, otp_code, expires_at)

    return {
        "message": f"Verification code successfully sent to {email}. Please check your inbox.",
        "email": email,
        "email_dispatched": True
    }


@router.post("/register/verify")
async def verify_and_register(req: RegisterVerifyRequest):
    email = req.email.strip().lower()
    username = req.username.strip()
    otp_code = "".join(c for c in req.otp if c.isdigit())

    if not req.password or len(req.password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters.")

    # Check Max Verification Attempts Limit
    attempts = otp_failed_attempts.get(email, 0)
    if attempts >= MAX_OTP_ATTEMPTS:
        if email in in_memory_otps:
            del in_memory_otps[email]
        otp_failed_attempts.pop(email, None)
        raise HTTPException(
            status_code=429,
            detail="Too many failed verification attempts. This code has been invalidated for security reasons. Please request a new code."
        )

    # 1. Verify against memory cache
    valid = False
    fail_reason = "Invalid or expired verification code."

    if email in in_memory_otps:
        cached = in_memory_otps[email]
        cached_otp = "".join(c for c in str(cached["otp"]) if c.isdigit())
        if cached_otp == otp_code:
            if cached["expires_at"] > time.time():
                valid = True
                del in_memory_otps[email]
                otp_failed_attempts.pop(email, None)
            else:
                fail_reason = "This verification code has expired. Please request a new code."
        else:
            otp_failed_attempts[email] = attempts + 1
            remaining = MAX_OTP_ATTEMPTS - (attempts + 1)
            fail_reason = f"Incorrect verification code ({remaining} attempts remaining)."

    # 2. Verify against MongoDB Atlas
    if not valid and email not in in_memory_otps:
        is_mongo_valid, reason = await db_verify_otp(email, otp_code)
        if is_mongo_valid:
            valid = True
            otp_failed_attempts.pop(email, None)
        else:
            otp_failed_attempts[email] = attempts + 1
            remaining = MAX_OTP_ATTEMPTS - (attempts + 1)
            fail_reason = f"{reason} ({remaining} attempts remaining)."

    if not valid:
        raise HTTPException(status_code=400, detail=fail_reason)
        if is_mongo_valid:
            valid = True
        else:
            fail_reason = reason

    if not valid:
        raise HTTPException(status_code=400, detail=fail_reason)

    role = req.role if req.role in ("Analyst", "Senior Analyst", "Admin") else "Analyst"
    created_at = datetime.now().isoformat()
    hashed_pwd = hash_password(req.password)

    new_user = {
        "username": username,
        "email": email,
        "password": hashed_pwd,
        "role": role,
        "created_at": created_at
    }

    # Save in memory and MongoDB Atlas
    users[username] = new_user
    await db_save_user(new_user)

    logger.info(f"Registered new security operator: {username} ({role})")

    return {
        "message": "Registration successful! You can now sign in.",
        "username": username,
        "role": role,
        "email": email
    }


@router.post("/profile/change-password")
async def change_password(req: ChangePasswordRequest):
    username = req.username.strip()
    curr_pwd = req.current_password
    new_pwd = req.new_password

    if len(new_pwd) < 6:
        raise HTTPException(status_code=400, detail="New password must be at least 6 characters.")

    new_hash = hash_password(new_pwd)

    # Check MongoDB user
    db_user = await db_find_user(username)
    if db_user:
        if not verify_password(curr_pwd, db_user.get("password", "")):
            raise HTTPException(status_code=400, detail="Current password is incorrect.")
        await db_update_user_password(username, new_hash)
        if username in users:
            users[username]["password"] = new_hash
        return {"message": "Password updated and securely hashed successfully!"}

    # Check in-memory user
    if username in users:
        if not verify_password(curr_pwd, users[username].get("password", "")):
            raise HTTPException(status_code=400, detail="Current password is incorrect.")
        users[username]["password"] = new_hash
        await db_save_user({**users[username], "password": new_hash})
        return {"message": "Password updated and securely hashed successfully!"}

    raise HTTPException(status_code=404, detail="User not found.")


@router.get("/profile/{username}")
async def get_profile(username: str):
    db_user = await db_find_user(username)
    if db_user:
        return {
            "username": db_user.get("username", username),
            "email": db_user.get("email", f"{username}@soar.local"),
            "role": db_user.get("role", "Analyst"),
            "created_at": db_user.get("created_at", "2026-01-01T00:00:00"),
            "status": "Active (MongoDB)"
        }

    user = users.get(username)
    if user:
        return {
            "username": username,
            "email": user.get("email", f"{username}@soar.local"),
            "role": user["role"],
            "created_at": user.get("created_at", "2026-01-01T00:00:00"),
            "status": "Active (In-Memory)"
        }

    raise HTTPException(status_code=404, detail="User not found")


@router.get("/users")
async def get_users():
    return [
        {"username": u, "role": info["role"]}
        for u, info in users.items()
    ]


@router.post("/approve-playbook")
def approve_playbook(user: dict = Depends(require_role("Senior Analyst", "Admin"))):
    return {
        "message": "Playbook approved",
        "approved_by": user.get("sub"),
        "role": user.get("role")
    }
