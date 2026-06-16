# FlaskGuard - Custom Web Application Firewall

FlaskGuard is a lightweight Web Application Firewall (WAF) and reverse proxy built with Flask. It sits in front of a web application, inspects incoming requests, blocks suspicious traffic, logs attacks, and provides an admin dashboard for monitoring security events.

Traffic flow:

```text
Visitor -> FlaskGuard -> Protected Website
```

## Features

| Feature | Details |
|---|---|
| Regex Detection | Detects SQL Injection, XSS, Path Traversal, Command Injection, and File Injection attempts. |
| ML Classifier | Uses a Naive Bayes model with character n-gram TF-IDF features to flag suspicious input. |
| File Upload Scanner | Checks filenames, extensions, magic bytes, text content, SVGs, archives, Office files, and double-extension tricks. |
| Rate Limiting | Uses `flask-limiter` to limit requests per IP address. |
| IP Blacklist | Tracks repeat offenders, auto-bans after repeated attacks, and supports manual ban/unban actions. |
| Attack Logger | Stores structured attack events in JSON and writes security logs. |
| Admin Dashboard | Shows attack stats, recent logs, detection methods, top IPs, and blacklist controls. |
| Reverse Proxy | Forwards safe traffic to the real website while blocking malicious requests before they reach it. |
| Docker Support | Includes Docker and Docker Compose setup for running FlaskGuard in front of a demo backend. |
| Admin Authentication | Protects `/admin` and `/admin/api/*` with HTTP Basic Auth. |

## Project Structure

```text
FlaskGuard/
|-- flaskguard/
|   |-- app.py              # Main Flask WAF app, middleware, admin routes, proxy route
|   |-- security.py         # Regex-based attack detection
|   |-- ml_classifier.py    # Naive Bayes ML model
|   |-- file_scanner.py     # Upload scanner
|   |-- ip_manager.py       # IP blacklist manager
|   |-- attack_logger.py    # JSON + file logging
|   |-- proxy.py            # Reverse proxy forwarding logic
|   `-- templates/
|       `-- dashboard.html  # Admin security dashboard
|-- demo_backend/           # Example website protected by FlaskGuard
|-- logs/                   # Root-level sample logs
|-- config.yml              # FlaskGuard configuration
|-- docker-compose.yml      # WAF + demo backend
|-- Dockerfile
`-- requirements.txt
```

## Quick Start Without Docker

Install dependencies:

```bash
pip install -r requirements.txt
```

Run FlaskGuard:

```bash
python -m flaskguard.app
```

Then open:

```text
Dashboard: http://127.0.0.1:5000/admin
```

Default admin login:

```text
Username: admin
Password: admin123
```

Change these credentials before exposing FlaskGuard to other users.

## Quick Start With Docker

Run the included FlaskGuard + demo website stack:

```bash
docker compose up --build
```

Then open:

```text
Protected website: http://localhost
Dashboard:         http://localhost/admin
```

To override the admin credentials in PowerShell:

```powershell
$env:ADMIN_USERNAME="your-admin-user"
$env:ADMIN_PASSWORD="your-strong-password"
docker compose up --build
```

On Linux/macOS:

```bash
ADMIN_USERNAME="your-admin-user" ADMIN_PASSWORD="your-strong-password" docker compose up --build
```

## Apply FlaskGuard To Any Website

FlaskGuard works as a reverse proxy, so it can protect any HTTP application: Flask, Django, Express, PHP, static sites, Docker services, or internal web apps.

1. Run the original website on a private/local address.
2. Set FlaskGuard's `backend_url` to that website.
3. Expose FlaskGuard to users instead of exposing the website directly.

Traffic flow:

```text
User -> FlaskGuard -> Protected Website
```

Configure the protected website in `config.yml`:

```yaml
backend_url: "http://your-website-host:port"
```

Common examples:

```yaml
# Local app running on your machine
backend_url: "http://host.docker.internal:3000"

# Another service in Docker Compose
backend_url: "http://website:5000"

# Internal server
backend_url: "http://192.168.1.50:8080"
```

You can also set the backend at runtime:

```powershell
$env:BACKEND_URL="http://host.docker.internal:3000"
docker compose up --build
```

For Docker Compose, connect FlaskGuard and the website to the same network:

```yaml
services:
  flaskguard:
    build: .
    ports:
      - "80:80"
    environment:
      - BACKEND_URL=http://website:5000

  website:
    build: ./your-website
    expose:
      - "5000"
```

Users should then access:

```text
http://your-flaskguard-host
```

not:

```text
http://your-backend-host
```

## Detection Pipeline

```text
Request
  -> Admin auth check for /admin
  -> IP blacklist check
  -> File upload scanner
  -> Regex detection
  -> ML classifier fallback
  -> Allow or block
```

When a malicious request is detected:

1. FlaskGuard blocks the request with `403`.
2. The attack is logged.
3. The source IP receives a strike.
4. After repeated strikes, the IP is temporarily blacklisted.

## Test Attack Payloads

SQL Injection:

```bash
curl "http://localhost/search?q=' OR 1=1 --"
```

XSS:

```bash
curl "http://localhost/search?q=<script>alert(1)</script>"
```

Path Traversal:

```bash
curl "http://localhost/search?q=../../etc/passwd"
```

Command Injection:

```bash
curl "http://localhost/search?q=; ls -la"
```

File Injection:

```bash
curl "http://localhost/search?q=php://input"
```

Normal request:

```bash
curl "http://localhost/search?q=laptop"
```

## Admin API Endpoints

All admin endpoints require Basic Auth when `admin_auth.enabled` is true.

| Endpoint | Method | Description |
|---|---|---|
| `/admin` | GET | Dashboard UI |
| `/admin/api/stats` | GET | Attack statistics |
| `/admin/api/attacks` | GET | Recent attack log |
| `/admin/api/blacklist` | GET | Active blacklist |
| `/admin/api/ban` | POST | Manually ban an IP |
| `/admin/api/unban` | POST | Unban an IP |
| `/admin/api/simulate` | POST | Seed demo attack data |
| `/admin/api/ml/status` | GET | Current ML model metadata |
| `/admin/api/ml/retrain` | POST | Retrain from baseline data, attack logs, and feedback |
| `/admin/api/ml/feedback` | POST | Add admin feedback for a payload |
| `/admin/api/ml/features` | GET | Show top model feature importances |

Example manual unban:

```bash
curl -u admin:admin123 \
  -X POST http://localhost/admin/api/unban \
  -H "Content-Type: application/json" \
  -d '{"ip":"127.0.0.1"}'
```

## Configuration

Main settings live in `config.yml`.

```yaml
backend_url: "http://backend:8080"
port: 5000
debug: false

admin_auth:
  enabled: true
  username: "admin"
  password: "admin123"

storage:
  log_dir: "flaskguard/logs"
  attacks_file: "flaskguard/logs/attacks.json"
  security_log_file: "flaskguard/logs/security.log"
  blacklist_file: "flaskguard/logs/blacklist.json"
  classifier_model_file: "flaskguard/models/classifier.pkl"
  classifier_meta_file: "flaskguard/models/model_meta.json"
  feedback_file: "flaskguard/logs/feedback.json"

rate_limiting:
  enabled: true
  default_limits:
    - "200 per day"
    - "100 per hour"

proxy:
  timeout_seconds: 10
  verify_tls: true

ip_blacklist:
  enabled: true
  threshold_strikes: 5
  ban_duration_minutes: 60

ml_classifier:
  enabled: true
  confidence_threshold: 0.70
```

Environment variables can override selected settings:

| Variable | Purpose |
|---|---|
| `BACKEND_URL` | Target website to protect |
| `PORT` | FlaskGuard port when running directly |
| `ADMIN_USERNAME` | Admin dashboard username |
| `ADMIN_PASSWORD` | Admin dashboard password |

Storage paths can be absolute or relative to the project root. For example, to store runtime data outside the package directory:

```yaml
storage:
  log_dir: "data/logs"
  attacks_file: "data/logs/attacks.json"
  security_log_file: "data/logs/security.log"
  blacklist_file: "data/logs/blacklist.json"
  classifier_model_file: "data/models/classifier.pkl"
  classifier_meta_file: "data/models/model_meta.json"
  feedback_file: "data/logs/feedback.json"
```

## Important Notes

FlaskGuard is useful for demos, experiments, portfolio work, and controlled internal deployments. Before using it for a public production website, strengthen these areas:

- Use strong admin credentials.
- Put HTTPS/TLS in front of FlaskGuard, usually with Nginx, Caddy, Traefik, or a cloud load balancer.
- Use shared storage such as Redis, SQLite, or Postgres for logs, IP bans, and rate limits.
- Add tests for detection rules, file scanning, blacklist behavior, and proxy behavior.
- Add request timeouts and production monitoring.
- Review false positives before blocking real user traffic.

## How It Compares To Enterprise WAFs

| FlaskGuard | Enterprise WAF |
|---|---|
| Regex + small ML model | Large rule engines, behavior analysis, threat intelligence |
| Local JSON logs | SIEM/cloud logging integrations |
| Simple IP blacklist | Distributed reputation systems |
| Demo-friendly dashboard | Production alerting, audit trails, RBAC |
| Good for learning and prototypes | Built for high-scale production traffic |

FlaskGuard is not a replacement for a mature enterprise WAF, but it is a practical demonstration of the core ideas behind one.
