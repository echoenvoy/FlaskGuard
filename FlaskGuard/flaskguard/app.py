import os
import hmac
from urllib.parse import unquote
from flask import Flask, request, jsonify, render_template, Response
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from flaskguard.config import config
from flaskguard.security import detect_attack
from flaskguard.file_scanner import scan_file
from flaskguard.ml_classifier import (
    add_feedback,
    get_feature_importance,
    get_model_status,
    ml_confidence,
    ml_detect,
    retrain_from_logs,
)
from flaskguard.attack_logger import log_attack, get_recent, get_stats
from flaskguard.ip_manager import is_blacklisted, record_strike, manual_ban, unban, get_blacklist
from flaskguard.proxy import forward_request

app = Flask(__name__)
app.secret_key = config.get("secret_key", "flaskguard-secret-change-in-production-key")

# Setup Rate Limiter
limiter_kwargs = {
    "key_func": get_remote_address,
    "app": app,
    "storage_uri": "memory://",
}

if config.get("rate_limiting", {}).get("enabled", True):
    limiter_kwargs["default_limits"] = config["rate_limiting"].get("default_limits", ["200 per day", "50 per hour"])
else:
    limiter_kwargs["default_limits"] = []

limiter = Limiter(**limiter_kwargs)


def _is_excluded_path(path: str) -> bool:
    for excluded in config.get("exclude_paths", []):
        if path == excluded or path.startswith(excluded.rstrip("/") + "/"):
            return True
    return False


def _is_static_asset_request() -> bool:
    if request.method not in {"GET", "HEAD", "OPTIONS"}:
        return False

    _, ext = os.path.splitext(request.path.lower())
    return ext in set(config.get("static_asset_extensions", []))


def _path_payload_parts() -> list:
    path = unquote(request.path or "")
    parts = []

    # Decode the full path for regex detection so encoded payloads are visible.
    if path:
        parts.append(path)

    # For API search routes, the payload is often a path segment rather than a
    # query parameter, for example /api/product/list/search/<payload>.
    if "/search/" in path:
        payload = path.rsplit("/search/", 1)[1]
        if payload:
            parts.append(payload)

    return parts


def _admin_auth_required():
    admin_auth = config.get("admin_auth", {})
    if not admin_auth.get("enabled", True):
        return False
    return request.path.startswith("/admin")


def _check_admin_credentials(username: str, password: str) -> bool:
    admin_auth = config.get("admin_auth", {})
    expected_user = str(admin_auth.get("username", "admin"))
    expected_pass = str(admin_auth.get("password", ""))
    return (
        hmac.compare_digest(username or "", expected_user)
        and hmac.compare_digest(password or "", expected_pass)
    )


def _admin_auth_challenge():
    return Response(
        "Admin authentication required",
        401,
        {"WWW-Authenticate": 'Basic realm="FlaskGuard Admin"'},
    )


@app.before_request
def admin_auth_middleware():
    if not _admin_auth_required():
        return

    auth = request.authorization
    if not auth or not _check_admin_credentials(auth.username, auth.password):
        return _admin_auth_challenge()

# ─────────────────────────────────────────────
# Security Middleware
# ─────────────────────────────────────────────

@app.before_request
def security_middleware():
    ip = request.remote_addr

    # Skip admin dashboard itself from WAF check
    if request.path.startswith("/admin"):
        return

    # Check IP blacklist
    if config.get("ip_blacklist", {}).get("enabled", True):
        if is_blacklisted(ip):
            return jsonify({"error": "Access denied — IP blacklisted"}), 403

    # Check if request path is excluded or is a frontend static asset.
    if _is_excluded_path(request.path) or _is_static_asset_request():
        return

    # 1) File upload scanner
    if config.get("file_scanner", {}).get("enabled", True) and request.files:
        for field, fs in request.files.items():
            file_result = scan_file(fs)
            if not file_result["safe"]:
                auto_banned = record_strike(ip) if config.get("ip_blacklist", {}).get("enabled", True) else False
                log_attack(
                    ip=ip,
                    method=request.method,
                    path=request.path,
                    user_agent=request.headers.get("User-Agent", ""),
                    payload=f"filename={fs.filename};reason={file_result['reason']};detail={file_result['detail']}",
                    category=file_result["threat"],
                    detection_method="File Scanner",
                    auto_banned=auto_banned,
                )
                msg = "Malicious file detected"
                if auto_banned:
                    msg += " — IP auto-banned"
                return jsonify({
                    "error": msg,
                    "category": file_result["threat"],
                    "detail": file_result["detail"],
                    "filename": fs.filename,
                }), 403

    # Collect user-controlled input data for ML analysis.
    user_parts = []
    if request.args:
        user_parts.extend(request.args.values())
    if request.form:
        user_parts.extend(request.form.values())
    
    # Safely handle JSON parsing (in case of malformed request body)
    if request.is_json:
        try:
            json_data = request.get_json(silent=True)
            if json_data:
                user_parts.append(str(json_data))
        except Exception:
            pass

    path_parts = _path_payload_parts()

    # Regex rules can inspect path + input, but ML should only judge actual user input.
    regex_parts = [request.full_path, *path_parts, *user_parts]
    regex_payload = " ".join(str(part) for part in regex_parts)
    ml_payload = " ".join(str(part) for part in [*user_parts, *path_parts[1:]])

    if not regex_payload.strip():
        return

    # 2) Regex detection
    result = detect_attack(regex_payload)
    detection_method = None
    category = None
    logged_payload = regex_payload

    if result["malicious"]:
        detection_method = "Regex"
        category = result["category"]
    else:
        # 3) ML Classifier detection
        if config.get("ml_classifier", {}).get("enabled", True) and len(ml_payload) >= 3:
            confidence = ml_confidence(ml_payload)
            threshold = config["ml_classifier"].get("confidence_threshold", 0.70) * 100
            if confidence > threshold:
                detection_method = "ML Classifier"
                category = "Suspicious Input"
                logged_payload = ml_payload

    if detection_method:
        auto_banned = record_strike(ip) if config.get("ip_blacklist", {}).get("enabled", True) else False
        log_attack(
            ip=ip,
            method=request.method,
            path=request.path,
            user_agent=request.headers.get("User-Agent", ""),
            payload=logged_payload[:300],
            category=category,
            detection_method=detection_method,
            auto_banned=auto_banned,
        )
        msg = "Malicious input detected"
        if auto_banned:
            msg += " — IP auto-banned"
        return jsonify({"error": msg, "category": category}), 403


# ─────────────────────────────────────────────
# Admin Dashboard Routing
# ─────────────────────────────────────────────

@app.route("/admin")
@limiter.exempt
def admin_dashboard():
    return render_template("dashboard.html")


@app.route("/admin/api/stats")
@limiter.exempt
def api_stats():
    return jsonify(get_stats())


@app.route("/admin/api/attacks")
@limiter.exempt
def api_attacks():
    limit = int(request.args.get("limit", 50))
    return jsonify(get_recent(limit))


@app.route("/admin/api/blacklist")
@limiter.exempt
def api_blacklist():
    return jsonify(get_blacklist())


@app.route("/admin/api/ban", methods=["POST"])
@limiter.exempt
def api_ban():
    data = request.json or {}
    ip = data.get("ip")
    minutes = int(data.get("minutes", 60))
    if not ip:
        return jsonify({"error": "IP required"}), 400
    manual_ban(ip, minutes)
    return jsonify({"message": f"Banned {ip} for {minutes} minutes"})


@app.route("/admin/api/unban", methods=["POST"])
@limiter.exempt
def api_unban():
    data = request.json or {}
    ip = data.get("ip")
    if not ip:
        return jsonify({"error": "IP required"}), 400
    unban(ip)
    return jsonify({"message": f"Unbanned {ip}"})


@app.route("/admin/api/ml/status")
@limiter.exempt
def api_ml_status():
    return jsonify(get_model_status())


@app.route("/admin/api/ml/retrain", methods=["POST"])
@limiter.exempt
def api_ml_retrain():
    result = retrain_from_logs()
    if result.get("status") == "error":
        return jsonify(result), 400
    return jsonify(result)


@app.route("/admin/api/ml/feedback", methods=["POST"])
@limiter.exempt
def api_ml_feedback():
    data = request.json or {}
    payload = data.get("payload", "").strip()
    is_attack = bool(data.get("is_attack", True))
    if not payload:
        return jsonify({"error": "payload required"}), 400
    return jsonify(add_feedback(payload, is_attack))


@app.route("/admin/api/ml/features")
@limiter.exempt
def api_ml_features():
    top_n = int(request.args.get("top", 20))
    features = get_feature_importance(top_n=top_n)
    return jsonify({"features": features, "count": len(features)})


@app.route("/admin/api/simulate", methods=["POST"])
@limiter.exempt
def simulate_attacks():
    """Seed fake attack telemetry for demonstration."""
    import random
    fake_ips = ["192.168.1.10", "10.0.0.55", "172.16.0.3", "203.0.113.42"]
    fake_payloads = [
        ("' OR 1=1 --", "SQL Injection", "Regex"),
        ("UNION SELECT password FROM users", "SQL Injection", "Regex"),
        ("<script>alert('xss')</script>", "XSS", "Regex"),
        ("../../etc/passwd", "Path Traversal", "Regex"),
        ("; ls -la", "Command Injection", "Regex"),
        ("eval(atob('test'))", "XSS", "ML Classifier"),
        ("' AND SLEEP(5)--", "SQL Injection", "ML Classifier"),
    ]

    for _ in range(20):
        ip = random.choice(fake_ips)
        payload, cat, method = random.choice(fake_payloads)
        log_attack(
            ip=ip,
            method="POST",
            path="/login",
            user_agent="Mozilla/5.0 (attacker)",
            payload=payload,
            category=cat,
            detection_method=method,
            auto_banned=False
        )

    return jsonify({"message": "20 simulated attacks logged"})


# ─────────────────────────────────────────────
# Reverse Proxy Wildcard Routing
# ─────────────────────────────────────────────

@app.route("/", defaults={"path": ""}, methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"])
@app.route("/<path:path>", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"])
def proxy(path):
    # Do not proxy requests intended for admin panel (should be handled by routes above, but as a safeguard)
    if path.startswith("admin"):
        return "Not Found", 404

    backend_url = config.get("backend_url", "http://backend:8080")
    proxy_config = config.get("proxy", {})
    timeout = proxy_config.get("timeout_seconds", 10)
    verify_tls = proxy_config.get("verify_tls", True)
    return forward_request(backend_url, path, timeout=timeout, verify_tls=verify_tls)


if __name__ == "__main__":
    # Pre-train ML model if not already present
    from flaskguard.ml_classifier import train_model
    train_model()
    
    port = int(config.get("port", 5000))
    debug = bool(config.get("debug", False))
    print(f"🛡  FlaskGuard WAF Proxy starting on port {port}...")
    print(f"   Dashboard: http://127.0.0.1:{port}/admin")
    print(f"   Protecting: {config.get('backend_url')}")
    app.run(host="0.0.0.0", port=port, debug=debug)
