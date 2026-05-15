"""
OpenRails Monitor — Piattaforma Web v1.0
Backend Flask con SQLite
"""

from flask import Flask, request, jsonify, render_template, session, redirect, url_for
from functools import wraps
import sqlite3, hashlib, os, secrets, re
from datetime import datetime

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))

DB_PATH = os.path.join(os.path.dirname(__file__), "orm.db")

# ─────────────────────────────────────────────────────────
#  Database
# ─────────────────────────────────────────────────────────

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            nome          TEXT    NOT NULL,
            cognome       TEXT    NOT NULL,
            username      TEXT    NOT NULL UNIQUE,
            email         TEXT    NOT NULL UNIQUE,
            password_hash TEXT    NOT NULL,
            api_token     TEXT    NOT NULL UNIQUE,
            created_at    TEXT    DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS heartbeats (
            user_id     INTEGER PRIMARY KEY REFERENCES users(id),
            last_seen   TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS sessions (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id     INTEGER NOT NULL REFERENCES users(id),
            punteggio   REAL    NOT NULL,
            ultimo_servizio TEXT NOT NULL,
            frenate_brusche INTEGER DEFAULT 0,
            accel_brusche   INTEGER DEFAULT 0,
            penalita        REAL    DEFAULT 0.0,
            completamento   INTEGER DEFAULT 0,
            durata_min      REAL    DEFAULT 0.0,
            grade           TEXT    DEFAULT '',
            registrata_at   TEXT    DEFAULT (datetime('now'))
        );
        """)

init_db()

# ─────────────────────────────────────────────────────────
#  Utility
# ─────────────────────────────────────────────────────────

def hash_password(pw: str) -> str:
    return hashlib.sha256(pw.encode()).hexdigest()

def require_login(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login_page"))
        return f(*args, **kwargs)
    return decorated

def validate_email(email: str) -> bool:
    return bool(re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email))

# ─────────────────────────────────────────────────────────
#  Pagine HTML
# ─────────────────────────────────────────────────────────

@app.route("/")
def index():
    return redirect(url_for("leaderboard_page"))

@app.route("/register")
def register_page():
    return render_template("register.html")

@app.route("/login")
def login_page():
    return render_template("login.html")

@app.route("/leaderboard")
def leaderboard_page():
    return render_template("leaderboard.html")

@app.route("/profile")
@require_login
def profile_page():
    return render_template("profile.html")

# ─────────────────────────────────────────────────────────
#  API Auth
# ─────────────────────────────────────────────────────────

@app.route("/api/register", methods=["POST"])
def api_register():
    data = request.get_json(force=True) or {}
    nome     = (data.get("nome", "") or "").strip()
    cognome  = (data.get("cognome", "") or "").strip()
    username = (data.get("username", "") or "").strip()
    email    = (data.get("email", "") or "").strip().lower()
    password = data.get("password", "") or ""

    if not all([nome, cognome, username, email, password]):
        return jsonify({"ok": False, "error": "Tutti i campi sono obbligatori"}), 400
    if len(password) < 6:
        return jsonify({"ok": False, "error": "La password deve essere di almeno 6 caratteri"}), 400
    if not validate_email(email):
        return jsonify({"ok": False, "error": "Email non valida"}), 400
    if len(username) < 3:
        return jsonify({"ok": False, "error": "Username troppo corto (min 3 caratteri)"}), 400

    token = secrets.token_hex(32)
    try:
        with get_db() as conn:
            conn.execute(
                "INSERT INTO users (nome, cognome, username, email, password_hash, api_token) VALUES (?,?,?,?,?,?)",
                (nome, cognome, username, email, hash_password(password), token)
            )
        return jsonify({"ok": True, "message": "Registrazione completata!"})
    except sqlite3.IntegrityError as e:
        if "username" in str(e):
            return jsonify({"ok": False, "error": "Username già in uso"}), 409
        return jsonify({"ok": False, "error": "Email già registrata"}), 409

@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json(force=True) or {}
    username = (data.get("username", "") or "").strip()
    password = data.get("password", "") or ""

    if not username or not password:
        return jsonify({"ok": False, "error": "Credenziali mancanti"}), 400

    with get_db() as conn:
        user = conn.execute(
            "SELECT * FROM users WHERE (username=? OR email=?) AND password_hash=?",
            (username, username, hash_password(password))
        ).fetchone()

    if not user:
        return jsonify({"ok": False, "error": "Credenziali non valide"}), 401

    session["user_id"] = user["id"]
    session["username"] = user["username"]
    return jsonify({"ok": True, "username": user["username"]})

@app.route("/api/logout", methods=["POST"])
def api_logout():
    session.clear()
    return jsonify({"ok": True})

@app.route("/api/me")
def api_me():
    if "user_id" not in session:
        return jsonify({"logged_in": False})
    with get_db() as conn:
        user = conn.execute("SELECT * FROM users WHERE id=?", (session["user_id"],)).fetchone()
    if not user:
        return jsonify({"logged_in": False})
    # Statistiche utente
    stats = conn.execute("""
        SELECT COUNT(*) as runs, MAX(punteggio) as best, AVG(punteggio) as avg
        FROM sessions WHERE user_id=?
    """, (user["id"],)).fetchone()
    return jsonify({
        "logged_in": True,
        "username": user["username"],
        "nome": user["nome"],
        "cognome": user["cognome"],
        "email": user["email"],
        "api_token": user["api_token"],
        "created_at": user["created_at"],
        "runs": stats["runs"] or 0,
        "best_score": round(stats["best"] or 0, 1),
        "avg_score": round(stats["avg"] or 0, 1),
    })

# ─────────────────────────────────────────────────────────
#  API Leaderboard
# ─────────────────────────────────────────────────────────

@app.route("/api/leaderboard")
def api_leaderboard():
    with get_db() as conn:
        rows = conn.execute("""
            SELECT
                u.username,
                MAX(s.punteggio)    AS punteggio,
                s.ultimo_servizio,
                s.grade,
                COUNT(s.id)         AS corse,
                CASE
                    WHEN h.last_seen >= datetime('now', '-2 minutes')
                    THEN 1 ELSE 0
                END                 AS online
            FROM sessions s
            JOIN users u ON u.id = s.user_id
            LEFT JOIN heartbeats h ON h.user_id = s.user_id
            GROUP BY s.user_id
            ORDER BY punteggio DESC
            LIMIT 100
        """).fetchall()
    return jsonify([dict(r) for r in rows])

@app.route("/api/my_sessions")
def api_my_sessions():
    if "user_id" not in session:
        return jsonify({"ok": False, "error": "Non autenticato"}), 401
    with get_db() as conn:
        rows = conn.execute("""
            SELECT punteggio, ultimo_servizio, grade, frenate_brusche,
                   accel_brusche, penalita, completamento, registrata_at
            FROM sessions WHERE user_id=?
            ORDER BY registrata_at DESC LIMIT 50
        """, (session["user_id"],)).fetchall()
    return jsonify([dict(r) for r in rows])

# ─────────────────────────────────────────────────────────
#  API ricezione dati dall'EXE (autenticazione via token)
# ─────────────────────────────────────────────────────────

@app.route("/api/submit", methods=["POST"])
def api_submit():
    """
    Endpoint chiamato dal file .exe per inviare i dati di una sessione.
    Header richiesto: X-API-Token: <token>
    Body JSON:
      {
        "punteggio": 85.3,
        "ultimo_servizio": "Roma Termini → Firenze SMN",
        "frenate_brusche": 2,
        "accel_brusche": 1,
        "penalita": 5.0,
        "completamento": 100,
        "durata_min": 45.2,
        "grade": "Buono"
      }
    """
    token = request.headers.get("X-API-Token", "").strip()
    if not token:
        return jsonify({"ok": False, "error": "Token mancante"}), 401

    with get_db() as conn:
        user = conn.execute("SELECT * FROM users WHERE api_token=?", (token,)).fetchone()
    if not user:
        return jsonify({"ok": False, "error": "Token non valido"}), 401

    data = request.get_json(force=True) or {}
    try:
        punteggio       = float(data.get("punteggio", 0))
        ultimo_servizio = str(data.get("ultimo_servizio", "Sconosciuto"))[:200]
        frenate         = int(data.get("frenate_brusche", 0))
        accel           = int(data.get("accel_brusche", 0))
        penalita        = float(data.get("penalita", 0.0))
        completamento   = int(data.get("completamento", 0))
        durata_min      = float(data.get("durata_min", 0.0))
        grade           = str(data.get("grade", ""))[:20]
    except (ValueError, TypeError) as e:
        return jsonify({"ok": False, "error": f"Dati non validi: {e}"}), 400

    with get_db() as conn:
        conn.execute("""
            INSERT INTO sessions
              (user_id, punteggio, ultimo_servizio, frenate_brusche, accel_brusche,
               penalita, completamento, durata_min, grade)
            VALUES (?,?,?,?,?,?,?,?,?)
        """, (user["id"], punteggio, ultimo_servizio, frenate, accel,
              penalita, completamento, durata_min, grade))

    return jsonify({"ok": True, "message": "Sessione registrata!"})

# ─────────────────────────────────────────────────────────
#  API heartbeat (dal .exe, ogni 60s mentre è aperto)
# ─────────────────────────────────────────────────────────

@app.route("/api/heartbeat", methods=["POST"])
def api_heartbeat():
    """
    Chiamato dal .exe ogni 60 secondi per segnalare che è online.
    Header richiesto: X-API-Token: <token>
    """
    token = request.headers.get("X-API-Token", "").strip()
    if not token:
        return jsonify({"ok": False, "error": "Token mancante"}), 401

    with get_db() as conn:
        user = conn.execute("SELECT id FROM users WHERE api_token=?", (token,)).fetchone()
    if not user:
        return jsonify({"ok": False, "error": "Token non valido"}), 401

    with get_db() as conn:
        conn.execute("""
            INSERT INTO heartbeats (user_id, last_seen)
            VALUES (?, datetime('now'))
            ON CONFLICT(user_id) DO UPDATE SET last_seen=datetime('now')
        """, (user["id"],))

    return jsonify({"ok": True})

# ─────────────────────────────────────────────────────────

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
