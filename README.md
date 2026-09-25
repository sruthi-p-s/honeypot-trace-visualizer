Web Honeypot & Forensic Attack Trace Visualizer

A defensive cybersecurity web application built using Python Flask and MySQL (XAMPP). The application deploys decoy endpoints (/admin, /.env, /wp-login.php) designed to lure automated crawlers and malicious actors. When a probe is detected, the system extracts critical forensic artifacts—including remote IP address, targeted URL, HTTP method, user-agent string, and submitted payloads—and commits them into a relational database. A role-authenticated SOC dashboard allows analysts to inspect, triage, and manage incident traces in real time.

Key Cybersecurity Features
Deception Routing (Honeypot Decoys): Exposed endpoints simulate vulnerable infrastructure to catch automated scans and brute-force attempts without exposing internal assets.

Forensic Artifact Acquisition: Automatically harvests client IP, request headers, HTTP methods, and raw payloads at the moment of interaction.

Heuristic Threat Scoring: Evaluates incoming request parameters for known attack signatures (SQL injection, XSS) and dynamically assigns threat severities.

Authenticated Incident Triage: SOC analysts access an authenticated interface protected by salted password hashing (werkzeug.security) to inspect, review, or purge incident logs.

System Architecture & Tech Stack
Backend: Python 3 (Flask Framework)

Database: MySQL on XAMPP (honeypot_db)

Database Driver: mysql-connector-python

Authentication & Cryptography: werkzeug.security

Frontend: Jinja2 Templates, HTML5, Bootstrap 5, CSS3

Attacker / Client ───► [ Decoy Endpoints (/admin, /.env) ] 
                                  │
                                  ▼ (Extracts IP, Headers, Payload)
                           [ Flask Engine ]
                                  │ (Stores Artifacts)
                                  ▼
                         [ MySQL (XAMPP) ]
                                  ▲
                                  │ (Queries Traces & Auth)
SOC Analyst ─────────► [ Secure Portal (/portal/login) ] ───► [ Triage Dashboard ]
Database Schema Design
Database Name: honeypot_db

Table 1: analysts (Authentication Management)

Field	Type	Attributes	Description
id	INT	PRIMARY KEY, AUTO_INCREMENT	Unique identifier for the analyst
username	VARCHAR(50)	UNIQUE, NOT NULL	Analyst username
password_hash	VARCHAR(255)	NOT NULL	Salted cryptographic password hash
created_at	TIMESTAMP	DEFAULT CURRENT_TIMESTAMP	Account creation timestamp


Table 2: attack_logs (Forensic Artifact Registry)

Field	Type	Attributes	Description
id	INT	PRIMARY KEY, AUTO_INCREMENT	Unique log entry sequence
attacker_ip	VARCHAR(45)	NOT NULL	Captured remote IPv4/IPv6 address
endpoint_targeted	VARCHAR(255)	NOT NULL	Specific trap URL requested
http_method	VARCHAR(10)	NOT NULL	Method used (GET, POST)
user_agent	TEXT	NULL	Client browser/scanner fingerprint
payload	TEXT	NULL	Submitted form data, injection strings, or probes
threat_level	VARCHAR(20)	DEFAULT 'Suspicious'	Rule-based triage score (Medium / High)
captured_at	TIMESTAMP	DEFAULT CURRENT_TIMESTAMP	Incident event timestamp
Setup & Installation
Start Services:

Start Apache and MySQL from the XAMPP Control Panel.

Open phpMyAdmin (http://localhost/phpmyadmin) and import honeypot_db.sql.

Install Dependencies:

Bash
pip install flask mysql-connector-python werkzeug
Run Application:

Bash
python app.py
Access Points:

Decoy Gateway: [http://127.0.0.1:5000/admin](http://127.0.0.1:5000/admin)

Analyst Portal: [http://127.0.0.1:5000/portal/login](http://127.0.0.1:5000/portal/login)

Default Credentials: admin / admin@123
