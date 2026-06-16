"""
FlaskGuard - Attack Logger
Stores events to JSON log + Python logging
"""

import json
import os
import logging
import threading
from datetime import datetime

from flaskguard.config import get_storage_path


LOG_DIR = get_storage_path("log_dir", os.path.join("flaskguard", "logs"))
os.makedirs(LOG_DIR, exist_ok=True)

LOG_FILE = get_storage_path("attacks_file", os.path.join("flaskguard", "logs", "attacks.json"))
SECURITY_LOG_FILE = get_storage_path("security_log_file", os.path.join("flaskguard", "logs", "security.log"))
os.makedirs(os.path.dirname(SECURITY_LOG_FILE), exist_ok=True)
_lock = threading.Lock()

# Setup Python logger
logging.basicConfig(
    filename=SECURITY_LOG_FILE,
    level=logging.WARNING,
    format="%(asctime)s | %(levelname)s | %(message)s",
)


def _read_all() -> list:
    if not os.path.exists(LOG_FILE):
        return []
    with open(LOG_FILE) as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return []


def _write_all(events: list):
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    with open(LOG_FILE, "w") as f:
        json.dump(events, f, indent=2)


def log_attack(ip: str, method: str, path: str, user_agent: str,
               payload: str, category: str, detection_method: str,
               auto_banned: bool = False):
    event = {
        "timestamp": datetime.utcnow().isoformat(),
        "ip": ip,
        "method": method,
        "path": path,
        "user_agent": user_agent[:200],
        "payload": payload[:300],
        "category": category,
        "detection_method": detection_method,
        "auto_banned": auto_banned,
    }

    with _lock:
        events = _read_all()
        events.append(event)
        # Keep last 500 events
        events = events[-500:]
        _write_all(events)

    logging.warning(
        f"[{category}] {ip} -> {method} {path} | payload: {payload[:80]} | via: {detection_method}"
    )


def get_recent(limit: int = 100) -> list:
    with _lock:
        events = _read_all()
        return list(reversed(events[-limit:]))


def get_stats() -> dict:
    with _lock:
        events = _read_all()

    total = len(events)
    if total == 0:
        return {
            "total": 0, "by_category": {}, "top_ips": [],
            "by_method": {}, "recent_24h": 0, "auto_banned": 0
        }

    from collections import Counter
    from datetime import timedelta

    by_cat = Counter(e["category"] for e in events)
    by_ip = Counter(e["ip"] for e in events)
    by_method = Counter(e["detection_method"] for e in events)
    cutoff = (datetime.utcnow() - timedelta(hours=24)).isoformat()
    recent = sum(1 for e in events if e["timestamp"] > cutoff)
    auto_banned = sum(1 for e in events if e.get("auto_banned"))

    return {
        "total": total,
        "by_category": dict(by_cat.most_common()),
        "top_ips": [{"ip": ip, "count": c} for ip, c in by_ip.most_common(5)],
        "by_method": dict(by_method),
        "recent_24h": recent,
        "auto_banned": auto_banned,
    }
