"""
OpenRails Monitor — Piattaforma Web v1.1
Backend Flask con PostgreSQL (persistente su Render)
"""

from flask import Flask, request, jsonify, render_template, session, redirect, url_for
from functools import wraps
import psycopg2, psycopg2.extras, psycopg2.errorcodes
import hashlib, os, secrets, re

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))

DATABASE_URL = os.environ.get("DATABASE_URL", "")

# ─────────────────────────────────────────────────────────
#  Database
# ─────────────────────────────────────────────────────────

def get_db():
    conn = psycopg2.connect(DATABASE_URL)
    return conn

def fetchone(cur):
    row = cur.fetchone()
    if row is None:
        return None
    cols = [d[0] for d in cur.description]
    return dict(zip(cols, row))

def fetchall(cur):
    cols = [d[0] for d in cur.description]
    return [dict(zip(cols, row)) for row in cur.fetchall()]

def init_db():
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id            SERIAL PRIMARY KEY,
                nome          TEXT    NOT NULL,
                cognome       TEXT    NOT NULL,
                username      TEXT    NOT NULL UNIQUE,
                email         TEXT    NOT NULL UNIQUE,
                password_hash TEXT    NOT NULL,
                api_token     TEXT    NOT NULL UNIQUE,
                created_at    TIMESTAMPTZ DEFAULT NOW()
            );
            CREATE TABLE IF NOT EXISTS heartbeats (
                user_id     INTEGER PRIMARY KEY REFERENCES users(id),
                last_seen   TIMESTAMPTZ NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sessions (
                id              SERIAL PRIMARY KEY,
                user_id         INTEGER NOT NULL REFERENCES users(id),
                punteggio       REAL    NOT NULL,
                ultimo_servizio TEXT    NOT NULL,
                frenate_brusche INTEGER DEFAULT 0,
                accel_brusche   INTEGER DEFAULT 0,
                penalita        REAL    DEFAULT 0.0,
                completamento   INTEGER DEFAULT 0,
                durata_min      REAL    DEFAULT 0.0,
                grade           TEXT    DEFAULT '',
                registrata_at   TIMESTAMPTZ DEFAULT NOW()
            );
            """)
        conn.commit()

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
    data     = request.get_json(force=True) or {}
    nome     = (data.get("nome",     "") or "").strip()
    cognome  = (data.get("cognome",  "") or "").strip()
    username = (data.get("username", "") or "").strip()
    email    = (data.get("email",    "") or "").strip().lower()
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
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO users (nome, cognome, username, email, password_hash, api_token) "
                    "VALUES (%s,%s,%s,%s,%s,%s)",
                    (nome, cognome, username, email, hash_password(password), token)
                )
            conn.commit()
        return jsonify({"ok": True, "message": "Registrazione completata!"})
    except psycopg2.errors.UniqueViolation as e:
        msg = str(e)
        if "username" in msg:
            return jsonify({"ok": False, "error": "Username già in uso"}), 409
        return jsonify({"ok": False, "error": "Email già registrata"}), 409

@app.route("/api/login", methods=["POST"])
def api_login():
    data     = request.get_json(force=True) or {}
    username = (data.get("username", "") or "").strip()
    password = data.get("password", "") or ""

    if not username or not password:
        return jsonify({"ok": False, "error": "Credenziali mancanti"}), 400

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT * FROM users WHERE (username=%s OR email=%s) AND password_hash=%s",
                (username, username, hash_password(password))
            )
            user = fetchone(cur)

    if not user:
        return jsonify({"ok": False, "error": "Credenziali non valide"}), 401

    session["user_id"]  = user["id"]
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
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM users WHERE id=%s", (session["user_id"],))
            user = fetchone(cur)
            if not user:
                return jsonify({"logged_in": False})
            cur.execute(
                "SELECT COUNT(*) as runs, MAX(punteggio) as best, AVG(punteggio) as avg "
                "FROM sessions WHERE user_id=%s", (user["id"],)
            )
            stats = fetchone(cur)
    return jsonify({
        "logged_in":  True,
        "username":   user["username"],
        "nome":       user["nome"],
        "cognome":    user["cognome"],
        "email":      user["email"],
        "api_token":  user["api_token"],
        "created_at": str(user["created_at"]),
        "runs":       stats["runs"] or 0,
        "best_score": round(float(stats["best"] or 0), 1),
        "avg_score":  round(float(stats["avg"]  or 0), 1),
    })

# ─────────────────────────────────────────────────────────
#  API Leaderboard
# ─────────────────────────────────────────────────────────

@app.route("/api/leaderboard")
def api_leaderboard():
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT
                    u.username,
                    MAX(s.punteggio)    AS punteggio,
                    s.ultimo_servizio,
                    s.grade,
                    COUNT(s.id)         AS corse,
                    CASE
                        WHEN h.last_seen >= NOW() - INTERVAL '2 minutes'
                        THEN 1 ELSE 0
                    END                 AS online
                FROM sessions s
                JOIN users u ON u.id = s.user_id
                LEFT JOIN heartbeats h ON h.user_id = s.user_id
                GROUP BY s.user_id, u.username, s.ultimo_servizio, s.grade, h.last_seen
                ORDER BY punteggio DESC
                LIMIT 100
            """)
            rows = fetchall(cur)
    return jsonify(rows)

@app.route("/api/my_sessions")
def api_my_sessions():
    if "user_id" not in session:
        return jsonify({"ok": False, "error": "Non autenticato"}), 401
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT punteggio, ultimo_servizio, grade, frenate_brusche,
                       accel_brusche, penalita, completamento,
                       registrata_at::text AS registrata_at
                FROM sessions WHERE user_id=%s
                ORDER BY registrata_at DESC LIMIT 50
            """, (session["user_id"],))
            rows = fetchall(cur)
    return jsonify(rows)

# ─────────────────────────────────────────────────────────
#  API ricezione dati dall'EXE
# ─────────────────────────────────────────────────────────

@app.route("/api/submit", methods=["POST"])
def api_submit():
    token = request.headers.get("X-API-Token", "").strip()
    if not token:
        return jsonify({"ok": False, "error": "Token mancante"}), 401
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM users WHERE api_token=%s", (token,))
            user = fetchone(cur)
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
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO sessions
                  (user_id, punteggio, ultimo_servizio, frenate_brusche, accel_brusche,
                   penalita, completamento, durata_min, grade)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
            """, (user["id"], punteggio, ultimo_servizio, frenate, accel,
                  penalita, completamento, durata_min, grade))
        conn.commit()
    return jsonify({"ok": True, "message": "Sessione registrata!"})

# ─────────────────────────────────────────────────────────
#  API heartbeat (dal .exe, ogni 60s)
# ─────────────────────────────────────────────────────────

@app.route("/api/heartbeat", methods=["POST"])
def api_heartbeat():
    token = request.headers.get("X-API-Token", "").strip()
    if not token:
        return jsonify({"ok": False, "error": "Token mancante"}), 401
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM users WHERE api_token=%s", (token,))
            user = fetchone(cur)
    if not user:
        return jsonify({"ok": False, "error": "Token non valido"}), 401
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO heartbeats (user_id, last_seen)
                VALUES (%s, NOW())
                ON CONFLICT (user_id) DO UPDATE SET last_seen = NOW()
            """, (user["id"],))
        conn.commit()
    return jsonify({"ok": True})

# ─────────────────────────────────────────────────────────

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
