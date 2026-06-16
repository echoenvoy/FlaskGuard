# FlaskGuard - Custom Web Application Firewall (WAF) & E-Commerce Stack

This repository showcases a complete security architecture demonstrating **FlaskGuard**—a custom-built Web Application Firewall (WAF) and reverse proxy—deployed to protect a full-stack MERN (MongoDB, Express, React, Node.js) e-commerce application.

---

##  Project Structure

```text
FlaskGuard-main/
├── FlaskGuard/          # Web Application Firewall (WAF) & Reverse Proxy (Python/Flask)
├── Test website/        # MERN Stack E-commerce web application (Target Website)
├── Documentation/       # Team reports, presentations, and individual contributions
└── start.txt            # Docker Compose startup helper script
```

###  1. [FlaskGuard](./FlaskGuard) (WAF & Reverse Proxy)
The core security layer. It acts as a reverse proxy, standing in front of the e-commerce website to inspect incoming HTTP requests and shield it from web attacks.
* **Multi-Stage Detection:** Employs regex signatures, file scanners (verifying upload extensions, magic bytes, SVGs, archives, etc.), rate limiting, and a Naive Bayes Machine Learning model fallback to detect SQL Injection, XSS, Path Traversal, and Command Injection.
* **IP Blacklisting:** Tracks malicious requests, assigns strikes to offender IPs, and bans them temporarily after a threshold.
* **Security Dashboard:** Provides an admin panel (`/admin`) with real-time statistics, event logs, IP blacklist controls, and feedback tools to retrain the ML classifier.

###  2. [Test website](./Test%20website) (MERN E-Commerce App)
A full-featured MERN stack application used as a live target to test and demonstrate the defensive capabilities of the WAF.
* **client/**: A React-based client web interface.
* **server/**: An Express/Node.js API backend communicating with MongoDB.
* **docker-compose.yml**: Orchestrates the multi-container stack: `flaskguard` (WAF), `client` (React), `server` (Express), and `mongo` (MongoDB).

### 3. [Documentation](./Documentation)
Contains structural reports and presentations illustrating the research, design, implementation, and results of the project:
* `Rapport global.pdf` - Consolidated group project report.
* `presentation.pdf` - Project defense slides.
* Individual reports for team members (Hamza, Amine, Ayoub, Mohamed, Abdelmoghit).

---

##  Quick Start (Running the Stack)

The entire environment is configured to run inside Docker.

1. Ensure **Docker Desktop** is running on your machine.
2. Open your terminal in the root of this project and run the commands in [start.txt](./start.txt):
   ```bash
   cd "Test website"
   docker compose build --no-cache flaskguard
   docker compose up --build
   ```
3. Access the services in your browser:
   * **Protected Website:** [http://localhost](http://localhost) (Traffic goes through FlaskGuard)
   * **WAF Security Dashboard:** [http://localhost/admin](http://localhost/admin) (Default Credentials: `admin` / `admin123`)

##  Contributors

This project was developed collaboratively by:

* Amhidi Hamza
* Saaf Ayyoub
* Saoud Amine
* Ben Mouh Mohamed
* El Asraoui Abdelmoghit

