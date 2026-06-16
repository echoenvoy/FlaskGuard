import os
import yaml

DEFAULT_CONFIG = {
    "backend_url": "http://backend:8080",
    "port": 5000,
    "debug": False,
    "secret_key": "flaskguard-secret-change-in-production-key",
    "admin_auth": {
        "enabled": True,
        "username": "admin",
        "password": "admin123"
    },
    "storage": {
        "log_dir": "flaskguard/logs",
        "attacks_file": "flaskguard/logs/attacks.json",
        "security_log_file": "flaskguard/logs/security.log",
        "blacklist_file": "flaskguard/logs/blacklist.json",
        "classifier_model_file": "flaskguard/models/classifier.pkl",
        "classifier_meta_file": "flaskguard/models/model_meta.json",
        "feedback_file": "flaskguard/logs/feedback.json"
    },
    "rate_limiting": {
        "enabled": True,
        "default_limits": ["200 per day", "100 per hour"]
    },
    "proxy": {
        "timeout_seconds": 10,
        "verify_tls": True
    },
    "ip_blacklist": {
        "enabled": True,
        "threshold_strikes": 5,
        "ban_duration_minutes": 60
    },
    "ml_classifier": {
        "enabled": True,
        "confidence_threshold": 0.85
    },
    "file_scanner": {
        "enabled": True,
        "max_file_size_mb": 10,
        "allowed_extensions": {
            "image": [".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp"],
            "document": [".pdf", ".txt", ".csv", ".json", ".xml"],
            "archive": [".zip"],
            "office": [".docx", ".xlsx", ".pptx"],
            "vector": [".svg"]
        }
    },
    "exclude_paths": ["/static", "/favicon.ico"],
    "static_asset_extensions": [
        ".css", ".js", ".map", ".ico", ".png", ".jpg", ".jpeg", ".gif", ".webp",
        ".svg", ".woff", ".woff2", ".ttf", ".eot", ".json", ".txt", ".xml"
    ]
}

# The config file should be located at the root of the project (one level above this package)
base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASE_DIR = base_dir
config_path = os.path.join(base_dir, "config.yml")

config = DEFAULT_CONFIG.copy()

if os.path.exists(config_path):
    try:
        with open(config_path, "r") as f:
            user_config = yaml.safe_load(f)
            if user_config:
                # Merge nested dictionaries to preserve defaults where key-value pairs are omitted
                for k, v in user_config.items():
                    if isinstance(v, dict) and k in config and isinstance(config[k], dict):
                        config[k].update(v)
                    else:
                        config[k] = v
    except Exception as e:
        print(f"[-] Error loading config.yml, falling back to default configuration. Error: {e}")
else:
    print(f"[*] config.yml not found at {config_path}, using default configuration.")

# Environment variables override config settings
if os.environ.get("BACKEND_URL"):
    config["backend_url"] = os.environ.get("BACKEND_URL")
if os.environ.get("PORT"):
    try:
        config["port"] = int(os.environ.get("PORT"))
    except ValueError:
        pass
if os.environ.get("ADMIN_USERNAME"):
    config.setdefault("admin_auth", {})["username"] = os.environ.get("ADMIN_USERNAME")
if os.environ.get("ADMIN_PASSWORD"):
    config.setdefault("admin_auth", {})["password"] = os.environ.get("ADMIN_PASSWORD")
if os.environ.get("PROXY_VERIFY_TLS"):
    value = os.environ.get("PROXY_VERIFY_TLS", "").strip().lower()
    config.setdefault("proxy", {})["verify_tls"] = value not in {"0", "false", "no", "off"}


def resolve_path(path: str) -> str:
    if os.path.isabs(path):
        return path
    return os.path.join(BASE_DIR, path)


def get_storage_path(key: str, fallback: str) -> str:
    storage = config.get("storage", {})
    return resolve_path(storage.get(key) or fallback)
