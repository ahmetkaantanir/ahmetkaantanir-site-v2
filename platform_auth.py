"""Optional named API principals with read, analyst, collector and admin roles."""
import hmac
import json
import os


def principal(token):
    key = os.getenv("LOG_LAB_API_KEY", "")
    if len(key) >= 24 and hmac.compare_digest(token.encode(), key.encode()):
        return {"name": "owner", "role": "admin"}
    try:
        entries = json.loads(os.getenv("LOG_LAB_PRINCIPALS", "[]"))
    except ValueError:
        entries = []
    if not isinstance(entries, list):
        return None
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        secret = entry.get("key", "")
        if (isinstance(secret, str) and len(secret) >= 24 and
                entry.get("role") in {"reader", "analyst", "collector", "admin"} and
                hmac.compare_digest(token.encode(), secret.encode())):
            return {"name": str(entry.get("name", "service"))[:80], "role": entry["role"]}
    return None


def permitted(identity, method, path):
    role = identity["role"]
    if role == "admin":
        return True
    if role == "collector":
        return method == "POST" and path == "/api/soc/ingest"
    if method in {"GET", "HEAD"}:
        return not path.endswith("/audit")
    return role == "analyst" and ("/cases/" in path or path.endswith("/watchlist") or
        "/watchlist/" in path or path.endswith("/ingest") or path.endswith("/sigma/test") or
        path.endswith("/forensics/verify") or "/platform/assistant/" in path or path.endswith('/intelligence/enrich'))
