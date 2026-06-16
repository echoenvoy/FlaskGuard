"""
FlaskGuard - IP Blacklist Manager
Tracks and blocks repeat offenders
"""

import json
import os
import threading
from datetime import datetime, timedelta
from collections import defaultdict

from flaskguard.config import config, get_storage_path


BLACKLIST_FILE = get_storage_path("blacklist_file", os.path.join("flaskguard", "logs", "blacklist.json"))
DEFAULT_THRESHOLD_STRIKES = 5
DEFAULT_BAN_DURATION_MINUTES = 60

_lock = threading.Lock()
_strike_counter = defaultdict(int)   # ip -> count (in-memory)
_blacklist = {}                       # ip -> expiry ISO string


def _blacklist_config() -> dict:
    return config.get("ip_blacklist", {})


def _threshold_strikes() -> int:
    try:
        return int(_blacklist_config().get("threshold_strikes", DEFAULT_THRESHOLD_STRIKES))
    except (TypeError, ValueError):
        return DEFAULT_THRESHOLD_STRIKES


def _ban_duration_minutes() -> int:
    try:
        return int(_blacklist_config().get("ban_duration_minutes", DEFAULT_BAN_DURATION_MINUTES))
    except (TypeError, ValueError):
        return DEFAULT_BAN_DURATION_MINUTES


def _load():
    global _blacklist
    if os.path.exists(BLACKLIST_FILE):
        try:
            with open(BLACKLIST_FILE) as f:
                _blacklist = json.load(f)
        except Exception:
            _blacklist = {}


def _save():
    os.makedirs(os.path.dirname(BLACKLIST_FILE), exist_ok=True)
    with open(BLACKLIST_FILE, "w") as f:
        json.dump(_blacklist, f, indent=2)


_load()


def is_blacklisted(ip: str) -> bool:
    with _lock:
        if ip not in _blacklist:
            return False
        expiry = datetime.fromisoformat(_blacklist[ip])
        if datetime.utcnow() > expiry:
            del _blacklist[ip]
            _save()
            return False
        return True


def record_strike(ip: str) -> bool:
    """Returns True if IP just got auto-banned."""
    with _lock:
        _strike_counter[ip] += 1
        if _strike_counter[ip] >= _threshold_strikes():
            expiry = datetime.utcnow() + timedelta(minutes=_ban_duration_minutes())
            _blacklist[ip] = expiry.isoformat()
            _save()
            _strike_counter[ip] = 0
            return True
        return False


def manual_ban(ip: str, minutes: int = None):
    with _lock:
        if minutes is None:
            minutes = _ban_duration_minutes()
        expiry = datetime.utcnow() + timedelta(minutes=minutes)
        _blacklist[ip] = expiry.isoformat()
        _save()


def unban(ip: str):
    with _lock:
        _blacklist.pop(ip, None)
        _save()


def get_blacklist() -> list:
    with _lock:
        now = datetime.utcnow()
        active = []
        to_remove = []
        for ip, expiry_str in _blacklist.items():
            expiry = datetime.fromisoformat(expiry_str)
            if now > expiry:
                to_remove.append(ip)
            else:
                remaining = int((expiry - now).total_seconds() // 60)
                active.append({"ip": ip, "expires": expiry_str, "remaining_min": remaining})
        for ip in to_remove:
            del _blacklist[ip]
        if to_remove:
            _save()
        return active
