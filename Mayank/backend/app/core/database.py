"""
MongoDB connection and persistence management using Motor (async driver).
Includes transparent fallback to in-memory store if MongoDB is offline or using placeholder URI.
"""
import asyncio
from motor.motor_asyncio import AsyncIOMotorClient
from app.core.config import settings
from app.core.logger import logger

client: AsyncIOMotorClient | None = None
db = None
is_connected: bool = False
connection_error: str | None = None


async def connect_db():
    """Connect to MongoDB with a short timeout and initialise collections / indexes."""
    global client, db, is_connected, connection_error
    uri = settings.MONGODB_URI or "mongodb://localhost:27017"
    
    # Check if URI is still the default unconfigured template or contains placeholder
    if "cluster.xxxxx.mongodb.net" in uri or "username:password" in uri or "<db_password>" in uri:
        is_connected = False
        connection_error = "Please replace <db_password> with your MongoDB user password in Mayank/backend/.env"
        logger.warning("MongoDB URI contains placeholder <db_password>. Operating in in-memory mode with MongoDB standby.")
        return False

    try:
        logger.info(f"Attempting connection to MongoDB ({settings.DB_NAME})...")
        client = AsyncIOMotorClient(uri, serverSelectionTimeoutMS=5000, connectTimeoutMS=5000)
        # Test connection with a fast ping
        await client.admin.command("ping")
        db = client[settings.DB_NAME]
        is_connected = True
        connection_error = None

        # Create indexes
        await db.alerts.create_index("alert_id", unique=True)
        await db.cases.create_index("case_id", unique=True)
        await db.users.create_index("username", unique=True)
        await db.counters.create_index("_id")

        # Seed default users if collection is empty
        if await db.users.count_documents({}) == 0:
            default_users = [
                {"username": "analyst", "password": "analyst123", "role": "Analyst"},
                {"username": "senior", "password": "senior123", "role": "Senior Analyst"},
                {"username": "admin", "password": "admin123", "role": "Admin"},
            ]
            await db.users.insert_many(default_users)
            logger.info("MongoDB: Seeded default users (analyst / senior / admin)")

        logger.info("MongoDB: Connected successfully and ready for operations.")
        return True
    except Exception as exc:
        is_connected = False
        connection_error = str(exc)
        logger.warning(f"MongoDB offline or unreachable ({exc}). Running with in-memory persistence.")
        return False


async def close_db():
    """Close MongoDB connection gracefully."""
    global client, db, is_connected
    if client:
        client.close()
        logger.info("MongoDB connection closed.")
    is_connected = False


def is_mongo_connected() -> bool:
    return is_connected


def get_db_info() -> dict:
    return {
        "connected": is_connected,
        "database": settings.DB_NAME,
        "status": "Connected (MongoDB)" if is_connected else "In-Memory (Standby for MongoDB)",
        "uri_configured": not ("cluster.xxxxx" in (settings.MONGODB_URI or "")),
        "error": connection_error
    }


# ── Persistence Helpers for Alerts, Cases, Timeline ──

async def db_save_alert(entry: dict):
    if is_connected and db is not None:
        try:
            # Store copy without mutating _id in memory
            doc = {k: v for k, v in entry.items() if k != "_id"}
            await db.alerts.update_one({"alert_id": doc["alert_id"]}, {"$set": doc}, upsert=True)
        except Exception as e:
            logger.error(f"Failed to save alert to MongoDB: {e}")


async def db_fetch_alerts() -> list:
    if is_connected and db is not None:
        try:
            cursor = db.alerts.find({}, {"_id": 0}).sort("alert_id", -1)
            return await cursor.to_list(length=1000)
        except Exception as e:
            logger.error(f"Failed to fetch alerts from MongoDB: {e}")
    return []


async def db_save_case(case_data: dict):
    if is_connected and db is not None:
        try:
            doc = {k: v for k, v in case_data.items() if k != "_id"}
            await db.cases.update_one({"case_id": doc["case_id"]}, {"$set": doc}, upsert=True)
        except Exception as e:
            logger.error(f"Failed to save case to MongoDB: {e}")


async def db_update_case(case_id: int, update_data: dict):
    if is_connected and db is not None:
        try:
            await db.cases.update_one({"case_id": case_id}, {"$set": update_data})
        except Exception as e:
            logger.error(f"Failed to update case in MongoDB: {e}")


async def db_delete_case(case_id: int):
    if is_connected and db is not None:
        try:
            await db.cases.delete_one({"case_id": case_id})
        except Exception as e:
            logger.error(f"Failed to delete case from MongoDB: {e}")


async def db_fetch_cases() -> list:
    if is_connected and db is not None:
        try:
            cursor = db.cases.find({}, {"_id": 0}).sort("case_id", 1)
            return await cursor.to_list(length=1000)
        except Exception as e:
            logger.error(f"Failed to fetch cases from MongoDB: {e}")
    return []


async def db_save_timeline_event(case_id: int, event: dict):
    if is_connected and db is not None:
        try:
            await db.timeline.update_one(
                {"case_id": case_id},
                {"$push": {"events": event}},
                upsert=True
            )
        except Exception as e:
            logger.error(f"Failed to save timeline event to MongoDB: {e}")


async def db_fetch_timeline(case_id: int) -> list:
    if is_connected and db is not None:
        try:
            doc = await db.timeline.find_one({"case_id": case_id}, {"_id": 0, "events": 1})
            if doc and "events" in doc:
                return doc["events"]
        except Exception as e:
            logger.error(f"Failed to fetch timeline from MongoDB: {e}")
    return []


# ── User & OTP Persistence ──

async def db_find_user(username_or_email: str) -> dict | None:
    if is_connected and db is not None:
        try:
            doc = await db.users.find_one(
                {"$or": [{"username": username_or_email}, {"email": username_or_email}]},
                {"_id": 0}
            )
            return doc
        except Exception as e:
            logger.error(f"Failed to find user in MongoDB: {e}")
    return None


async def db_save_user(user_data: dict):
    if is_connected and db is not None:
        try:
            doc = {k: v for k, v in user_data.items() if k != "_id"}
            await db.users.update_one({"username": doc["username"]}, {"$set": doc}, upsert=True)
            logger.info(f"User '{doc['username']}' saved to MongoDB Atlas.")
        except Exception as e:
            logger.error(f"Failed to save user to MongoDB: {e}")


async def db_update_user_password(username: str, new_password: str) -> bool:
    if is_connected and db is not None:
        try:
            result = await db.users.update_one({"username": username}, {"$set": {"password": new_password}})
            return result.modified_count > 0 or result.matched_count > 0
        except Exception as e:
            logger.error(f"Failed to update password in MongoDB: {e}")
    return False


async def db_save_otp(email: str, otp_code: str, expires_at: float):
    if is_connected and db is not None:
        try:
            await db.otps.update_one(
                {"email": email},
                {"$set": {"email": email, "otp": otp_code, "expires_at": expires_at}},
                upsert=True
            )
        except Exception as e:
            logger.error(f"Failed to save OTP to MongoDB: {e}")


async def db_verify_otp(email: str, otp_code: str) -> tuple[bool, str]:
    """Verify OTP from MongoDB. Returns (is_valid, reason_message)."""
    if is_connected and db is not None:
        try:
            import time
            import re
            clean_email = email.strip().lower()
            clean_otp = "".join(c for c in str(otp_code) if c.isdigit())

            # Find matching record by email with regex escaping (prevents ReDoS / regex injection)
            escaped_email = re.escape(clean_email)
            doc = await db.otps.find_one({"email": {"$regex": f"^{escaped_email}$", "$options": "i"}})
            if not doc:
                logger.warning(f"No active OTP found for {clean_email}")
                return False, "No active verification code found for this email. Please request a new code."

            stored_otp = "".join(c for c in str(doc.get("otp", "")) if c.isdigit())
            expires_at = doc.get("expires_at", 0)

            if time.time() > expires_at:
                logger.warning(f"OTP for {clean_email} has expired.")
                await db.otps.delete_one({"_id": doc["_id"]})
                return False, "This verification code has expired. Please request a new code."

            if stored_otp != clean_otp:
                logger.warning(f"OTP mismatch for {clean_email}: entered '{clean_otp}', expected '{stored_otp}'")
                return False, "Incorrect verification code. If you requested multiple codes, please use the one from the most recent email."

            # OTP matches and is not expired!
            await db.otps.delete_one({"_id": doc["_id"]})
            logger.info(f"OTP verified successfully for {clean_email}")
            return True, "OK"
        except Exception as e:
            logger.error(f"Failed to verify OTP in MongoDB: {e}")
            return False, f"Database error during verification: {e}"
    return False, "Database offline"

