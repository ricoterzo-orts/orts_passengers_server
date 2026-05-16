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
            CREATE TABLE IF NOT EXISTS live_sessions (
                user_id         INTEGER PRIMARY KEY REFERENCES users(id),
                speed_kmh       REAL    DEFAULT 0,
                comfort_live    REAL    DEFAULT 100,
                delay_min       REAL    DEFAULT 0,
                next_station    TEXT    DEFAULT '',
                consist         TEXT    DEFAULT '',
                sim_time        TEXT    DEFAULT '',
                activity_name   TEXT    DEFAULT '',
                updated_at      TIMESTAMPTZ DEFAULT NOW()
            );

            CREATE TABLE IF NOT EXISTS heartbeats (
                user_id     INTEGER PRIMARY KEY REFERENCES users(id),
                last_seen   TIMESTAMPTZ NOT NULL
            );
            CREATE TABLE IF NOT EXISTS speed_history (
                id          SERIAL PRIMARY KEY,
                user_id     INTEGER NOT NULL REFERENCES users(id),
                speed_kmh   REAL    NOT NULL,
                sim_time    TEXT    DEFAULT '',
                recorded_at TIMESTAMPTZ DEFAULT NOW()
            );

            CREATE TABLE IF NOT EXISTS live_stations (
                id              SERIAL PRIMARY KEY,
                user_id         INTEGER NOT NULL REFERENCES users(id),
                station_name    TEXT    NOT NULL,
                arrival         TEXT    DEFAULT '',
                departure       TEXT    DEFAULT '',
                delay_min       REAL    DEFAULT 0,
                passed          BOOLEAN DEFAULT FALSE,
                is_current      BOOLEAN DEFAULT FALSE,
                sort_order      INTEGER DEFAULT 0,
                updated_at      TIMESTAMPTZ DEFAULT NOW()
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

def migrate_db():
    """Aggiunge colonne mancanti a tabelle esistenti (migrazioni sicure)."""
    migrations = [
        # live_sessions: aggiungi comfort_live se mancante
        """ALTER TABLE live_sessions ADD COLUMN IF NOT EXISTS comfort_live REAL DEFAULT 100""",
        # live_sessions: aggiungi tutte le colonne nel caso la tabella fosse vecchia
        """ALTER TABLE live_sessions ADD COLUMN IF NOT EXISTS speed_kmh REAL DEFAULT 0""",
        """ALTER TABLE live_sessions ADD COLUMN IF NOT EXISTS delay_min REAL DEFAULT 0""",
        """ALTER TABLE live_sessions ADD COLUMN IF NOT EXISTS next_station TEXT DEFAULT ''""",
        """ALTER TABLE live_sessions ADD COLUMN IF NOT EXISTS consist TEXT DEFAULT ''""",
        """ALTER TABLE live_sessions ADD COLUMN IF NOT EXISTS sim_time TEXT DEFAULT ''""",
        """ALTER TABLE live_sessions ADD COLUMN IF NOT EXISTS activity_name TEXT DEFAULT ''""",
        """ALTER TABLE live_sessions ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT NOW()""",
    ]
    with get_db() as conn:
        with conn.cursor() as cur:
            for sql in migrations:
                try:
                    cur.execute(sql)
                except Exception:
                    pass  # colonna già esistente o altro errore non bloccante
        conn.commit()

migrate_db()

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

@app.route('/api/delete_profile', methods=['POST'])
def delete_profile():
    # Verifica che l'utente sia loggato (usando la sessione di Flask)
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'ok': False, 'error': 'Non autorizzato'}), 401

    try:
        # 1. Elimina le sessioni di guida dell'utente
        db.execute('DELETE FROM sessions WHERE user_id = ?', (user_id,))
        
        # 2. Elimina l'utente stesso
        db.execute('DELETE FROM users WHERE id = ?', (user_id,))
        
        db.commit()
        
        # 3. Pulisce la sessione del browser
        session.clear()
        
        return jsonify({'ok': True})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 500

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
                    END                 AS online,
                    ls.speed_kmh,
                    ls.delay_min,
                    ls.next_station,
                    ls.consist,
                    ls.sim_time,
                    ls.activity_name,
                    ls.comfort_live
                FROM sessions s
                JOIN users u ON u.id = s.user_id
                LEFT JOIN heartbeats h ON h.user_id = s.user_id
                LEFT JOIN live_sessions ls ON ls.user_id = s.user_id
                GROUP BY s.user_id, u.username, s.ultimo_servizio, s.grade,
                         h.last_seen, ls.speed_kmh, ls.delay_min, ls.next_station,
                         ls.consist, ls.sim_time, ls.activity_name, ls.comfort_live
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
    """
    Chiamato dal .exe ogni 30s con dati live.
    Header: X-API-Token: <token>
    Body JSON (opzionale):
      {
        "speed_kmh": 120.5,
        "delay_min": 2.3,
        "next_station": "Firenze SMN",
        "consist": "E464.001",
        "sim_time": "14:32",
        "activity_name": "Roma → Firenze"
      }
    """
    token = request.headers.get("X-API-Token", "").strip()
    if not token:
        return jsonify({"ok": False, "error": "Token mancante"}), 401
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM users WHERE api_token=%s", (token,))
            user = fetchone(cur)
    if not user:
        return jsonify({"ok": False, "error": "Token non valido"}), 401

    data = request.get_json(force=True) or {}
    speed_kmh    = float(data.get("speed_kmh",   0) or 0)
    delay_min    = float(data.get("delay_min",   0) or 0)
    next_station = str(data.get("next_station",  "") or "")[:100]
    consist      = str(data.get("consist",       "") or "")[:100]
    sim_time     = str(data.get("sim_time",      "") or "")[:10]
    activity_name= str(data.get("activity_name", "") or "")[:200]
    comfort_live = float(data.get("comfort_live", 100) or 100)

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO heartbeats (user_id, last_seen)
                VALUES (%s, NOW())
                ON CONFLICT (user_id) DO UPDATE SET last_seen = NOW()
            """, (user["id"],))
            cur.execute("""
                INSERT INTO live_sessions
                  (user_id, speed_kmh, delay_min, next_station, consist, sim_time, activity_name, comfort_live, updated_at)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,NOW())
                ON CONFLICT (user_id) DO UPDATE SET
                  speed_kmh=EXCLUDED.speed_kmh,
                  delay_min=EXCLUDED.delay_min,
                  next_station=EXCLUDED.next_station,
                  consist=EXCLUDED.consist,
                  sim_time=EXCLUDED.sim_time,
                  activity_name=EXCLUDED.activity_name,
                  comfort_live=EXCLUDED.comfort_live,
                  updated_at=NOW()
            """, (user["id"], speed_kmh, delay_min, next_station, consist, sim_time, activity_name, comfort_live))
            # Salva campione velocità nello storico (max 200 per utente)
            if speed_kmh > 0:
                cur.execute("""
                    INSERT INTO speed_history (user_id, speed_kmh, sim_time)
                    VALUES (%s, %s, %s)
                """, (user["id"], speed_kmh, sim_time))
                cur.execute("""
                    DELETE FROM speed_history WHERE user_id=%s
                    AND id NOT IN (
                        SELECT id FROM speed_history
                        WHERE user_id=%s ORDER BY recorded_at DESC LIMIT 200
                    )
                """, (user["id"], user["id"]))
        conn.commit()
    return jsonify({"ok": True})

# ─────────────────────────────────────────────────────────
#  API dati live (per sezione LIVE leaderboard)
# ─────────────────────────────────────────────────────────

@app.route("/api/live")
def api_live():
    """Restituisce tutti gli utenti online con dati live completi."""""
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT
                    u.username,
                    u.id        AS user_id,
                    ls.speed_kmh,
                    ls.delay_min,
                    ls.next_station,
                    ls.consist,
                    ls.sim_time,
                    ls.activity_name,
                    ls.updated_at::text AS updated_at
                FROM live_sessions ls
                JOIN users u ON u.id = ls.user_id
                JOIN heartbeats h ON h.user_id = ls.user_id
                WHERE h.last_seen >= NOW() - INTERVAL '2 minutes'
                ORDER BY ls.updated_at DESC
            """)
            users_online = fetchall(cur)

    # Per ogni utente online, carica storico velocità (ultimi 20 campioni)
    result = []
    for u in users_online:
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT speed_kmh, sim_time, recorded_at::text AS recorded_at
                    FROM speed_history
                    WHERE user_id=%s
                    ORDER BY recorded_at DESC LIMIT 40
                """, (u["user_id"],))
                history = fetchall(cur)
                history.reverse()

                cur.execute("""
                    SELECT station_name, arrival, departure, delay_min,
                           passed, is_current, sort_order
                    FROM live_stations
                    WHERE user_id=%s
                    ORDER BY sort_order ASC
                """, (u["user_id"],))
                stations = fetchall(cur)

        u["speed_history"] = history
        u["stations"] = stations
        result.append(u)

    return jsonify(result)

@app.route("/api/live_stations", methods=["POST"])
def api_live_stations():
    """
    Riceve la lista delle stazioni con ritardi aggiornati dal .exe.
    Header: X-API-Token: <token>
    Body JSON:
      {
        "stations": [
          {"name": "Roma Termini", "arrival": "08:00", "departure": "08:05",
           "delay_min": 0, "passed": true, "is_current": false},
          {"name": "Firenze SMN", "arrival": "09:45", "departure": "09:50",
           "delay_min": 2.5, "passed": false, "is_current": true}
        ]
      }
    """
    token = request.headers.get("X-API-Token", "").strip()
    if not token:
        return jsonify({"ok": False, "error": "Token mancante"}), 401
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM users WHERE api_token=%s", (token,))
            user = fetchone(cur)
    if not user:
        return jsonify({"ok": False, "error": "Token non valido"}), 401

    data = request.get_json(force=True) or {}
    stations = data.get("stations", [])

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM live_stations WHERE user_id=%s", (user["id"],))
            for i, st in enumerate(stations):
                cur.execute("""
                    INSERT INTO live_stations
                      (user_id, station_name, arrival, departure, delay_min,
                       passed, is_current, sort_order)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
                """, (
                    user["id"],
                    str(st.get("name", ""))[:100],
                    str(st.get("arrival", "") or "")[:10],
                    str(st.get("departure", "") or "")[:10],
                    float(st.get("delay_min", 0) or 0),
                    bool(st.get("passed", False)),
                    bool(st.get("is_current", False)),
                    i
                ))
        conn.commit()
    return jsonify({"ok": True})

# ─────────────────────────────────────────────────────────

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
