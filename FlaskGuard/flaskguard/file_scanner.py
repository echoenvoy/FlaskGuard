"""
FlaskGuard - File Upload Scanner
Scans uploaded files for hidden malicious payloads:
  - SQL Injection in metadata, EXIF, text content
  - XSS scripts embedded in SVG / HTML files
  - Command injection strings in filenames or content
  - Path traversal in filenames or ZIP entries
  - Polyglot files (e.g. JPEG that is also a PHP/HTML file)
  - Malicious content hidden inside Office/ZIP archives
  - Double extension attacks (shell.php.jpg)
  - Null byte injection in filenames
  - Dangerous inner file types inside archives
"""

import io
import logging
import os
import re
import zipfile
from typing import Optional

from werkzeug.datastructures import FileStorage

from flaskguard.security import detect_attack

logger = logging.getLogger(__name__)

ALLOWED_EXTENSIONS = {
    "image": {".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp"},
    "document": {".pdf", ".txt", ".csv", ".json", ".xml"},
    "archive": {".zip"},
    "office": {".docx", ".xlsx", ".pptx"},
    "vector": {".svg"},
}

ALL_ALLOWED = set().union(*ALLOWED_EXTENSIONS.values())

DANGEROUS_INNER_EXT = {
    ".php", ".php3", ".php4", ".php5", ".phtml",
    ".exe", ".sh", ".bash", ".zsh", ".bat", ".cmd",
    ".js", ".vbs", ".ps1", ".py", ".rb", ".pl",
    ".asp", ".aspx", ".jsp", ".jspx", ".cfm",
}

MAGIC_BYTES = {
    b"\xff\xd8\xff": "image/jpeg",
    b"\x89PNG\r\n": "image/png",
    b"GIF87a": "image/gif",
    b"GIF89a": "image/gif",
    b"%PDF": "application/pdf",
    b"PK\x03\x04": "application/zip",
    b"<svg": "image/svg+xml",
    b"<!DOC": "text/html",
    b"<html": "text/html",
    b"<?php": "application/x-php",
    b"<?=": "application/x-php",
    b"#!": "application/x-script",
}

MAX_TEXT_SCAN_BYTES = 512 * 1024
MAX_FILE_SIZE = 10 * 1024 * 1024

EXTRA_PATTERNS = [
    r"<\?php",
    r"<\?=",
    r"<%[=@]?",
    r"^#!\s*/(?:usr/)?(?:local/)?bin/(?:bash|sh|zsh|python|perl|ruby|node)",
    r"(?i)(?:author|comment|description)\s*[:=]\s*['\"]?\s*(?:<script|' OR |UNION SELECT)",
    r"\x00",
    r"<!--#(?:exec|include|printenv)",
    r"(?i)(?:include|require)(?:_once)?\s*\(",
    r"(?i)\beval\s*\(",
    r"<!ENTITY",
    r"SYSTEM\s+['\"]",
    r"file:///",
    r"expect://",
    r"php://",
    r"data:text/html",
    r"<script",
    r"on\w+\s*=\s*['\"]",
    r"xlink:href\s*=\s*['\"]javascript",
    r"href\s*=\s*['\"]javascript",
    r"\{\{.*\}\}",
    r"\{%.*%\}",
    r"\*\)\(\|",
    r"'\s*or\s*'[^']*'\s*=\s*'",
]

_extra_compiled = [re.compile(p, re.IGNORECASE | re.MULTILINE) for p in EXTRA_PATTERNS]


def _scan_text_chunk(text: str) -> Optional[dict]:
    """Run main regex engine then file-specific extra patterns."""
    result = detect_attack(text)
    if result["malicious"]:
        return {
            "threat": result["category"],
            "detail": result["matched_pattern"],
            "source": "regex_engine",
        }
    for pat in _extra_compiled:
        match = pat.search(text)
        if match:
            return {
                "threat": "Embedded Malicious Code",
                "detail": match.group(0)[:80],
                "source": "file_scanner",
            }
    return None


def _detect_magic(raw: bytes) -> Optional[str]:
    for sig, mime in MAGIC_BYTES.items():
        if raw.startswith(sig):
            return mime
    return None


def _scan_exif_region(raw: bytes) -> Optional[dict]:
    """Extract printable ASCII runs (>=8 chars) from binary data and scan them."""
    printable = re.findall(rb"[ -~]{8,}", raw)
    combined = b" ".join(printable).decode("ascii", errors="ignore")
    if combined:
        return _scan_text_chunk(combined)
    return None


def _scan_zip_archive(raw: bytes) -> Optional[dict]:
    """Recursively inspect every entry in a ZIP/DOCX/XLSX/PPTX."""
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as zf:
            for entry in zf.infolist():
                fn_hit = _scan_text_chunk(entry.filename)
                if fn_hit:
                    return {**fn_hit, "zip_entry": entry.filename}

                _, inner_ext = os.path.splitext(entry.filename.lower())

                if inner_ext in DANGEROUS_INNER_EXT:
                    return {
                        "threat": "Dangerous File in Archive",
                        "detail": f"Forbidden inner extension '{inner_ext}' -> {entry.filename}",
                        "source": "file_scanner",
                        "zip_entry": entry.filename,
                    }

                text_inner = {
                    ".xml", ".html", ".htm", ".svg", ".txt", ".csv",
                    ".json", ".rels", ".vml", ".xsl", ".xslt", ".js",
                    ".css", ".md",
                }
                if inner_ext in text_inner:
                    try:
                        content = zf.read(entry.filename).decode("utf-8", errors="ignore")
                        hit = _scan_text_chunk(content)
                        if hit:
                            return {**hit, "zip_entry": entry.filename}
                    except Exception:
                        pass
    except zipfile.BadZipFile:
        pass
    return None


def _check_filename(filename: str) -> Optional[dict]:
    """Validate the raw filename for traversal, null bytes, double ext."""
    for candidate in [filename, os.path.basename(filename)]:
        hit = _scan_text_chunk(candidate)
        if hit:
            return {**hit, "detail": f"Malicious filename: {filename[:80]}"}

    if "\x00" in filename:
        return {
            "threat": "Null Byte Injection",
            "detail": "Null byte detected in filename",
            "source": "file_scanner",
        }

    parts = filename.rsplit(".", 2)
    if len(parts) == 3:
        hidden_ext = f".{parts[1].lower()}"
        if hidden_ext in DANGEROUS_INNER_EXT:
            return {
                "threat": "Double Extension Attack",
                "detail": f"Hidden dangerous extension '{hidden_ext}' inside '{filename}'",
                "source": "file_scanner",
            }

    return None


def scan_file(file: FileStorage) -> dict:
    filename = file.filename or ""
    _, ext = os.path.splitext(filename.lower())

    def _blocked(reason, threat, detail, source, zip_entry=None):
        return {
            "safe": False,
            "reason": reason,
            "threat": threat,
            "detail": detail,
            "source": source,
            "zip_entry": zip_entry,
        }

    fn_result = _check_filename(filename)
    if fn_result:
        return _blocked(
            "Malicious filename",
            fn_result["threat"], fn_result["detail"], fn_result["source"],
        )

    if ext not in ALL_ALLOWED:
        return _blocked(
            "Forbidden file extension",
            "Disallowed File Type",
            f"Extension '{ext}' is not permitted",
            "file_scanner",
        )

    raw = file.read(MAX_FILE_SIZE + 1)
    file.seek(0)

    if len(raw) > MAX_FILE_SIZE:
        return _blocked(
            "File too large",
            "Oversized Upload",
            f"File exceeds {MAX_FILE_SIZE // (1024 * 1024)} MB limit",
            "file_scanner",
        )

    if len(raw) == 0:
        return _blocked("Empty file", "Empty Upload", "Zero-byte file", "file_scanner")

    detected_mime = _detect_magic(raw)

    if detected_mime in ("application/x-php", "application/x-script"):
        return _blocked(
            "Executable content detected",
            "Server-Side Script Upload",
            f"File starts with PHP/shell magic bytes despite extension '{ext}'",
            "file_scanner",
        )

    if ext in ALLOWED_EXTENSIONS["image"] and detected_mime in ("text/html", None):
        text_chunk = raw[:MAX_TEXT_SCAN_BYTES].decode("utf-8", errors="ignore")
        poly = _scan_text_chunk(text_chunk)
        if poly:
            return _blocked("Polyglot file detected", poly["threat"], poly["detail"], poly["source"])

    is_zip_like = (
        detected_mime == "application/zip"
        or ext in (ALLOWED_EXTENSIONS["archive"] | ALLOWED_EXTENSIONS["office"])
    )

    if is_zip_like:
        zip_hit = _scan_zip_archive(raw)
        if zip_hit:
            return _blocked(
                "Malicious content inside archive",
                zip_hit["threat"], zip_hit["detail"], zip_hit["source"],
                zip_hit.get("zip_entry"),
            )

    if ext in ALLOWED_EXTENSIONS["image"]:
        exif_hit = _scan_exif_region(raw)
        if exif_hit:
            return _blocked(
                "Malicious payload in image metadata (EXIF)",
                exif_hit["threat"], exif_hit["detail"], exif_hit["source"],
            )

    text_exts = {".txt", ".csv", ".json", ".xml", ".svg", ".html", ".htm", ".pdf"}
    if ext in text_exts:
        text = raw[:MAX_TEXT_SCAN_BYTES].decode("utf-8", errors="ignore")
        txt_hit = _scan_text_chunk(text)
        if txt_hit:
            return _blocked(
                "Malicious payload in file content",
                txt_hit["threat"], txt_hit["detail"], txt_hit["source"],
            )

    return {
        "safe": True,
        "threat": None,
        "detail": None,
        "source": None,
        "zip_entry": None,
        "reason": None,
    }


def scan_multiple(files: list) -> dict:
    for f in files:
        result = scan_file(f)
        if not result["safe"]:
            result["filename"] = f.filename
            return result
    return {
        "safe": True,
        "threat": None,
        "detail": None,
        "source": None,
        "zip_entry": None,
        "reason": None,
        "filename": None,
    }
