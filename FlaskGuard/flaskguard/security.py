"""
FlaskGuard - Security Detection Engine
Regex + ML based injection/attack detection
"""

import re
import json
import logging
from datetime import datetime

# ─────────────────────────────────────────────
# Attack Pattern Definitions
# ─────────────────────────────────────────────

SQL_PATTERNS = [
    r"(?i)\bor\s+1\s*=\s*1\b",
    r"(?i)\band\s+1\s*=\s*1\b",
    r"(?i)\bunion\s+(all\s+)?select\b",
    r"--\s*$",
    r";\s*(drop|delete|truncate|alter)\s+",
    r"(?i)\binsert\s+into\b",
    r"(?i)\bdelete\s+from\b",
    r"(?i)\bdrop\s+table\b",
    r"(?i)\bexec(\s|\()",
    r"(?i)\bxp_cmdshell\b",
    r"(?i)\bsleep\s*\(",
    r"(?i)\bbenchmark\s*\(",
    r"(?i)'\s*or\s+'[^']*'\s*=\s*'",
    r"(?i)1\s*=\s*1",
]

XSS_PATTERNS = [
    r"<script[^>]*>",
    r"</script>",
    r"javascript\s*:",
    r"on\w+\s*=",
    r"<iframe",
    r"<img[^>]+onerror",
    r"document\.cookie",
    r"document\.write\s*\(",
    r"eval\s*\(",
    r"alert\s*\(",
    r"<svg[^>]*onload",
]

PATH_TRAVERSAL_PATTERNS = [
    r"\.\./",
    r"\.\.[\\\\]",
    r"%2e%2e%2f",
    r"%252e%252e",
    r"/etc/passwd",
    r"/etc/shadow",
    r"c:[\\\\]windows",
]

CMD_INJECTION_PATTERNS = [
    r";\s*(ls|cat|rm|wget|curl|chmod|bash|sh)\b",
    r"\|\s*(ls|cat|rm|wget|curl|bash|sh)\b",
    r"`[^`]*`",
    r"\$\([^)]*\)",
    r"&\s*(ls|cat|rm|wget|curl|bash|sh)\b",
]

FILE_INJECTION_PATTERNS = [
    # Local/remote file inclusion indicators
    r"(?i)(php|asp|jsp|cgi)://",
    r"(?i)\b(include|require)(_once)?\s*\(",
    r"(?i)(/proc/self/environ|php://input|data://|expect://)",
    r"(?i)(https?|ftp)://[^\s]+\.(php|phtml|jsp|aspx?)\b",
    # Malicious upload filename/content markers
    r"(?i)\.(php\d*|phtml|phar|jsp|jspx|asp|aspx|cgi|pl|exe|dll|sh|bat|ps1)\b",
    r"(?i)(<\?php|<%|#!/bin/(ba)?sh|powershell\s+-)",
    r"%00",
]

ATTACK_CATEGORIES = {
    "SQL Injection": SQL_PATTERNS,
    "XSS": XSS_PATTERNS,
    "Path Traversal": PATH_TRAVERSAL_PATTERNS,
    "Command Injection": CMD_INJECTION_PATTERNS,
    "File Injection": FILE_INJECTION_PATTERNS,
}


def detect_attack(input_data: str) -> dict:
    """
    Returns dict with keys:
        malicious (bool), category (str|None), matched_pattern (str|None)
    """
    if not input_data:
        return {"malicious": False, "category": None, "matched_pattern": None}

    for category, patterns in ATTACK_CATEGORIES.items():
        for pattern in patterns:
            match = re.search(pattern, input_data, re.IGNORECASE)
            if match:
                return {
                    "malicious": True,
                    "category": category,
                    "matched_pattern": match.group(0)[:80],
                }

    return {"malicious": False, "category": None, "matched_pattern": None}


def is_malicious(input_data: str) -> bool:
    return detect_attack(input_data)["malicious"]
