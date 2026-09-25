from flask import Flask, render_template, request, redirect, url_for, session, flash
import mysql.connector
from werkzeug.security import check_password_hash

app = Flask(__name__)
app.secret_key = "forensic_honeypot_secret_key"

# XAMPP MySQL Configuration
DB_CONFIG = {
    "host": "localhost",
    "user": "root",
    "password": "",
    "database": "honeypot_db"
}

def get_db_connection():
    return mysql.connector.connect(**DB_CONFIG)

def log_attack(endpoint, payload=""):
    """Extracts forensic traces and logs them into MySQL"""
    ip = request.remote_addr
    method = request.method
    ua = request.headers.get("User-Agent", "Unknown")
    
    # Simple rule-based threat assessment
    threat = "High" if any(k in str(payload).lower() for k in ["union", "select", "exec", "<script>"]) else "Medium"

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO attack_logs (attacker_ip, endpoint_targeted, http_method, user_agent, payload, threat_level)
        VALUES (%s, %s, %s, %s, %s, %s)
    """, (ip, endpoint, method, ua, str(payload), threat))
    conn.commit()
    cursor.close()
    conn.close()

# ----------------- DECOY / HONEYPOT ROUTES -----------------

@app.route("/")
def home():
    """Default public landing page"""
    return "<h3>System Status: Normal</h3><p>Internal network protected.</p>"

@app.route("/admin", methods=["GET", "POST"])
@app.route("/wp-login.php", methods=["GET", "POST"])
def honeypot_login():
    """Decoy login trap to catch unauthorized credentials"""
    if request.method == "POST":
        creds = request.form.to_dict()
        log_attack(request.path, payload=creds)
        flash("Invalid credentials.", "danger")
    else:
        log_attack(request.path, payload="Probe GET request")
    return render_template("fake_admin.html")

@app.route("/.env", methods=["GET"])
def honeypot_env():
    """Decoy config file trap"""
    log_attack("/.env", payload="Direct config grab attempt")
    return "DB_PASSWORD=fake_password_123", 403

# ----------------- ANALYST PORTAL (AUTHENTICATED) -----------------

@app.route("/portal/login", methods=["GET", "POST"])
def analyst_login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM analysts WHERE username = %s", (username,))
        user = cursor.fetchone()
        cursor.close()
        conn.close()

        if user and check_password_hash(user["password_hash"], password):
            session["analyst"] = user["username"]
            return redirect(url_for("dashboard"))
        flash("Invalid analyst credentials", "danger")

    return render_template("login.html")

@app.route("/portal/dashboard")
def dashboard():
    """READ Operation: View captured forensic traces"""
    if "analyst" not in session:
        return redirect(url_for("analyst_login"))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM attack_logs ORDER BY captured_at DESC")
    logs = cursor.fetchall()
    cursor.close()
    conn.close()

    return render_template("dashboard.html", logs=logs)

@app.route("/portal/delete/<int:log_id>", methods=["POST"])
def delete_log(log_id):
    """DELETE Operation: Remove false positives or processed traces"""
    if "analyst" not in session:
        return redirect(url_for("analyst_login"))

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM attack_logs WHERE id = %s", (log_id,))
    conn.commit()
    cursor.close()
    conn.close()

    return redirect(url_for("dashboard"))

@app.route("/portal/logout")
def logout():
    session.pop("analyst", None)
    return redirect(url_for("analyst_login"))

if __name__ == "__main__":
    app.run(debug=True, port=5000)