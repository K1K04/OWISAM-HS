#!/usr/bin/env python3
"""
portal.py — Captive Portal para laboratorio de ciberseguridad (TFM)
Simula un portal cautivo legítimo (tipo WiFi hotel/aeropuerto).
Registra nombre + email del cliente para "acceso a internet".
"""

from flask import Flask, request, render_template, redirect, jsonify, session
import sqlite3, os, datetime, hashlib, secrets

app = Flask(__name__)
app.jinja_env.tests['containing'] = lambda value, other: other in str(value) if value else False
app.secret_key = secrets.token_hex(16)

DB_PATH = os.path.join(os.path.dirname(__file__), "logs", "registrations.db")
ADMIN_TOKEN = "lab_admin_2024"   # Cambiar en producción

# ──────────────────────────────────────────────
# Base de datos
# ──────────────────────────────────────────────
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    with get_db() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS registrations (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                ts        TEXT    NOT NULL,
                ip        TEXT    NOT NULL,
                mac       TEXT,
                name      TEXT    NOT NULL,
                email     TEXT    NOT NULL,
                user_agent TEXT,
                accepted  INTEGER DEFAULT 0
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS dns_log (
                id    INTEGER PRIMARY KEY AUTOINCREMENT,
                ts    TEXT,
                ip    TEXT,
                query TEXT
            )
        """)

# ──────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────
def get_client_mac(ip: str) -> str:
    """Intenta obtener la MAC del cliente desde la tabla ARP."""
    try:
        with open("/proc/net/arp") as f:
            for line in f:
                parts = line.split()
                if parts[0] == ip:
                    return parts[3]
    except Exception:
        pass
    return "unknown"

def log_registration(name, email, ip, ua):
    mac = get_client_mac(ip)
    ts = datetime.datetime.now().isoformat(timespec="seconds")
    with get_db() as db:
        db.execute(
            "INSERT INTO registrations (ts, ip, mac, name, email, user_agent, accepted) VALUES (?,?,?,?,?,?,1)",
            (ts, ip, mac, name, email, ua)
        )
    print(f"[+] Registro: {ts} | {ip} ({mac}) | {name} <{email}>")

# ──────────────────────────────────────────────
# Connectivity checks — fuerzan apertura del portal en los OS
# ──────────────────────────────────────────────
CONNECTIVITY_PATHS = [
    "/generate_204",                    # Android / Chrome
    "/hotspot-detect.html",             # iOS / macOS
    "/ncsi.txt",                        # Windows NCSI
    "/connecttest.txt",                 # Windows 10+
    "/success.txt",                     # Firefox
    "/canonical.html",                  # Ubuntu
    "/library/test/success.html",       # macOS alt
]

@app.before_request
def intercept_connectivity_check():
    if request.path in CONNECTIVITY_PATHS:
        if "registered" in session:
            # Cliente ya registrado: devolver respuesta normal para no romper conexión
            if "204" in request.path:
                return "", 204
            return "Success", 200
        # Cliente no registrado: redirigir al portal
        return redirect("http://10.0.0.1:5000/portal", 302)

# ──────────────────────────────────────────────
# Rutas principales
# ──────────────────────────────────────────────
@app.route("/")
def index():
    if "registered" in session:
        return redirect("/success")
    return redirect("/portal")

@app.route("/portal")
def portal():
    return render_template("portal.html")

@app.route("/register", methods=["POST"])
def register():
    name  = request.form.get("name", "").strip()
    email = request.form.get("email", "").strip()
    ip    = request.remote_addr
    ua    = request.headers.get("User-Agent", "")

    if not name or not email or "@" not in email:
        return render_template("portal.html", error="Por favor rellena todos los campos correctamente.")

    log_registration(name, email, ip, ua)
    session["registered"] = True
    return redirect("/success")

@app.route("/success")
def success():
    return render_template("success.html")

# ──────────────────────────────────────────────
# Panel de administración (solo laboratorio)
# ──────────────────────────────────────────────
@app.route("/admin")
def admin():
    token = request.args.get("token", "")
    if token != ADMIN_TOKEN:
        return "Acceso denegado", 403
    with get_db() as db:
        rows = db.execute("SELECT * FROM registrations ORDER BY id DESC").fetchall()
    return render_template("admin.html", rows=rows, token=ADMIN_TOKEN)

@app.route("/admin/export")
def export_csv():
    token = request.args.get("token", "")
    if token != ADMIN_TOKEN:
        return "Acceso denegado", 403
    with get_db() as db:
        rows = db.execute("SELECT * FROM registrations ORDER BY id DESC").fetchall()
    lines = ["id,ts,ip,mac,name,email,user_agent"]
    for r in rows:
        lines.append(f'{r["id"]},{r["ts"]},{r["ip"]},{r["mac"]},{r["name"]},{r["email"]},"{r["user_agent"]}"')
    return "\n".join(lines), 200, {
        "Content-Type": "text/csv",
        "Content-Disposition": "attachment; filename=registrations.csv"
    }

@app.route("/admin/api/stats")
def api_stats():
    token = request.args.get("token", "")
    if token != ADMIN_TOKEN:
        return jsonify({"error": "forbidden"}), 403
    with get_db() as db:
        total   = db.execute("SELECT COUNT(*) FROM registrations").fetchone()[0]
        today   = db.execute("SELECT COUNT(*) FROM registrations WHERE ts LIKE ?", (datetime.date.today().isoformat() + "%",)).fetchone()[0]
        last_ip = db.execute("SELECT ip FROM registrations ORDER BY id DESC LIMIT 1").fetchone()
    return jsonify({"total": total, "today": today, "last_ip": last_ip[0] if last_ip else None})

# ──────────────────────────────────────────────
if __name__ == "__main__":
    init_db()
    print("[*] Portal cautivo iniciado en http://10.0.0.1:5000")
    print(f"[*] Admin panel: http://10.0.0.1:5000/admin?token={ADMIN_TOKEN}")
    app.run(host="0.0.0.0", port=5000, debug=False)
