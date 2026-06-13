"""
OpenRails Monitor — Piattaforma Web v1.2 (SECURE)
Backend Flask con PostgreSQL (persistente su Render)

Modifiche sicurezza rispetto a v1.1:
  - Password hashate con bcrypt (invece di SHA-256 semplice)
  - SESSION_COOKIE_SECURE = True
  - Rate limiting su login/register/submit (Flask-Limiter)
  - reCAPTCHA secret rimosso dal codice → solo env var
  - CSRF protection su endpoint sensibili (token in sessione)
  - Validazione username più restrittiva (solo [a-zA-Z0-9_.-])
  - Endpoint per rigenerare api_token
  - Logging tentativi di login falliti
"""

from flask import Flask, request, jsonify, render_template, session, redirect, url_for
from functools import wraps
import psycopg2, psycopg2.extras, psycopg2.errorcodes
import os, secrets, re, logging
from collections import defaultdict

import bcrypt
import requests
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from datetime import timedelta, date

# ─────────────────────────────────────────────────────────
#  App setup
# ─────────────────────────────────────────────────────────

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))

app.config["SESSION_COOKIE_SECURE"]   = True   # ← era False, CORRETTO
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Strict"  # ← era "Lax", più sicuro
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=30)

# reCAPTCHA secret SOLO da env var — mai hardcoded nel codice
RECAPTCHA_SECRET = os.environ.get("RECAPTCHA_SECRET", "")

DATABASE_URL = os.environ.get("DATABASE_URL", "")


# ─────────────────────────────────────────────────────────
#  Logging
# ─────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────
#  Notifiche Discord (webhook)
# ─────────────────────────────────────────────────────────

DISCORD_WEBHOOK_URL = os.environ.get("DISCORD_WEBHOOK_URL", "")
DISCORD_CRON_SECRET = os.environ.get("DISCORD_CRON_SECRET", "")

def notify_discord(content=None, embed=None):
    """Invia una notifica al webhook Discord. Non blocca/solleva mai
    eccezioni: un fallimento qui non deve mai rompere la request principale."""
    if not DISCORD_WEBHOOK_URL:
        return
    payload = {}
    if content:
        payload["content"] = content
    if embed:
        payload["embeds"] = [embed]
    if not payload:
        return
    try:
        requests.post(DISCORD_WEBHOOK_URL, json=payload, timeout=5)
    except Exception:
        logger.warning("Invio notifica Discord fallito", exc_info=True)

# ─────────────────────────────────────────────────────────
#  Helper badge / traguardi
# ─────────────────────────────────────────────────────────

def _streak_for_days(days):
    """days: set di date. Ritorna la lunghezza dello streak attivo
    (giorni consecutivi fino a oggi o ieri; 0 se la streak si è interrotta)."""
    if not days:
        return 0
    oggi = date.today()
    if oggi in days:
        cursore = oggi
    elif (oggi - timedelta(days=1)) in days:
        cursore = oggi - timedelta(days=1)
    else:
        return 0
    streak = 0
    while cursore in days:
        streak += 1
        cursore -= timedelta(days=1)
    return streak

def _primato_user_ids(cur):
    """Ritorna l'insieme di user_id che detengono il punteggio più alto
    su almeno una linea (ultimo_servizio)."""
    cur.execute("""
        WITH best_per_user AS (
            SELECT ultimo_servizio, user_id, MAX(punteggio) AS best
            FROM sessions
            WHERE ultimo_servizio <> ''
            GROUP BY ultimo_servizio, user_id
        ),
        ranked AS (
            SELECT ultimo_servizio, user_id,
                   RANK() OVER (PARTITION BY ultimo_servizio ORDER BY best DESC) AS rnk
            FROM best_per_user
        )
        SELECT DISTINCT user_id FROM ranked WHERE rnk=1
    """)
    return {r["user_id"] for r in fetchall(cur)}

def _primati_for_user(cur, user_id):
    """Ritorna le linee (con punteggio) dove user_id ha il record assoluto."""
    cur.execute("""
        WITH best_per_user AS (
            SELECT ultimo_servizio, user_id, MAX(punteggio) AS best
            FROM sessions
            WHERE ultimo_servizio <> ''
            GROUP BY ultimo_servizio, user_id
        ),
        ranked AS (
            SELECT ultimo_servizio, user_id, best,
                   RANK() OVER (PARTITION BY ultimo_servizio ORDER BY best DESC) AS rnk
            FROM best_per_user
        )
        SELECT ultimo_servizio, best
        FROM ranked
        WHERE user_id=%s AND rnk=1
        ORDER BY ultimo_servizio
    """, (user_id,))
    return fetchall(cur)

# ─────────────────────────────────────────────────────────
#  Rate Limiting
# ─────────────────────────────────────────────────────────

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=[],
    storage_uri=os.environ.get("REDIS_URL", "memory://")
)

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
            CREATE TABLE IF NOT EXISTS station_coords (
                id          SERIAL PRIMARY KEY,
                name        TEXT    NOT NULL UNIQUE,
                lat         REAL    NOT NULL,
                lon         REAL    NOT NULL,
                updated_at  TIMESTAMPTZ DEFAULT NOW()
            );
            CREATE TABLE IF NOT EXISTS user_stats (
                user_id         INTEGER PRIMARY KEY REFERENCES users(id),
                affidabilita    REAL    DEFAULT 0,
                ultima_tratta   TEXT    DEFAULT '',
                grade           TEXT    DEFAULT '',
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
    migrations = [
        """CREATE TABLE IF NOT EXISTS station_coords (
            id SERIAL PRIMARY KEY,
            name TEXT NOT NULL UNIQUE,
            lat REAL NOT NULL,
            lon REAL NOT NULL,
            updated_at TIMESTAMPTZ DEFAULT NOW()
        )""",
        """CREATE TABLE IF NOT EXISTS user_stats (
            user_id INTEGER PRIMARY KEY REFERENCES users(id),
            affidabilita REAL DEFAULT 0,
            ultima_tratta TEXT DEFAULT '',
            grade TEXT DEFAULT '',
            updated_at TIMESTAMPTZ DEFAULT NOW()
        )""",
        """ALTER TABLE live_sessions ADD COLUMN IF NOT EXISTS comfort_live REAL DEFAULT 100""",
        """ALTER TABLE live_sessions ADD COLUMN IF NOT EXISTS comfort_grade TEXT DEFAULT ''""",
        """ALTER TABLE live_sessions ADD COLUMN IF NOT EXISTS comfort_penalty REAL DEFAULT 0""",
        """ALTER TABLE live_sessions ADD COLUMN IF NOT EXISTS speed_kmh REAL DEFAULT 0""",
        """ALTER TABLE live_sessions ADD COLUMN IF NOT EXISTS delay_min REAL DEFAULT 0""",
        """ALTER TABLE live_sessions ADD COLUMN IF NOT EXISTS next_station TEXT DEFAULT ''""",
        """ALTER TABLE live_sessions ADD COLUMN IF NOT EXISTS consist TEXT DEFAULT ''""",
        """ALTER TABLE live_sessions ADD COLUMN IF NOT EXISTS sim_time TEXT DEFAULT ''""",
        """ALTER TABLE live_sessions ADD COLUMN IF NOT EXISTS activity_name TEXT DEFAULT ''""",
        """ALTER TABLE live_sessions ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT NOW()""",
        """ALTER TABLE live_sessions ADD COLUMN IF NOT EXISTS train_lat REAL DEFAULT 0""",
        """ALTER TABLE live_sessions ADD COLUMN IF NOT EXISTS train_lon REAL DEFAULT 0""",
        """ALTER TABLE live_sessions ADD COLUMN IF NOT EXISTS train_dir REAL DEFAULT 0""",
        """ALTER TABLE users ADD COLUMN IF NOT EXISTS azienda TEXT DEFAULT ''""",
        """ALTER TABLE users ADD COLUMN IF NOT EXISTS compartimento TEXT DEFAULT ''""",
    ]
    with get_db() as conn:
        with conn.cursor() as cur:
            for sql in migrations:
                try:
                    cur.execute(sql)
                except Exception:
                    pass
        conn.commit()

migrate_db()

# ─────────────────────────────────────────────────────────
#  Utility — Password (bcrypt)
# ─────────────────────────────────────────────────────────

def hash_password(pw: str) -> str:
    """Genera hash bcrypt della password. Sicuro contro rainbow table."""
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt(rounds=12)).decode()

def check_password(pw: str, hashed: str) -> bool:
    """Verifica password contro hash bcrypt.
    Supporta anche hash SHA-256 legacy per utenti pre-migrazione."""
    try:
        # Tenta verifica bcrypt (nuovo formato)
        return bcrypt.checkpw(pw.encode(), hashed.encode())
    except Exception:
        # Fallback: confronto SHA-256 legacy (da rimuovere dopo migrazione completa)
        import hashlib
        return hashlib.sha256(pw.encode()).hexdigest() == hashed

def migrate_password_if_needed(user_id: int, pw: str, current_hash: str):
    """Se l'hash è SHA-256 legacy, lo aggiorna a bcrypt silenziosamente."""
    import hashlib
    if not current_hash.startswith("$2b$"):
        new_hash = hash_password(pw)
        try:
            with get_db() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "UPDATE users SET password_hash=%s WHERE id=%s",
                        (new_hash, user_id)
                    )
                conn.commit()
        except Exception:
            pass

# ─────────────────────────────────────────────────────────
#  Utility — Validazione
# ─────────────────────────────────────────────────────────

def validate_email(email: str) -> bool:
    return bool(re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email))

def validate_username(username: str) -> bool:
    """Solo lettere, numeri, underscore, punto, trattino. Lunghezza 3-30."""
    return bool(re.match(r"^[a-zA-Z0-9_.\-]{3,30}$", username))

# ─────────────────────────────────────────────────────────
#  Utility — Anti-spam: domini email usa-e-getta
# ─────────────────────────────────────────────────────────

DISPOSABLE_EMAIL_DOMAINS = {
    "mailinator.com", "10minutemail.com", "10minutemail.net", "guerrillamail.com",
    "guerrillamail.net", "guerrillamail.org", "guerrillamail.biz", "guerrillamailblock.com",
    "tempmail.com", "temp-mail.org", "throwawaymail.com", "yopmail.com", "yopmail.fr",
    "yopmail.net", "fakeinbox.com", "trashmail.com", "trashmail.net", "trashmail.me",
    "getnada.com", "maildrop.cc", "mailnesia.com", "mintemail.com", "mailcatch.com",
    "spamgourmet.com", "dispostable.com", "mohmal.com", "emailondeck.com",
    "tempinbox.com", "sharklasers.com", "mytemp.email", "moakt.com", "moakt.cc",
    "33mail.com", "anonbox.net", "spambog.com", "spambog.de", "spambog.ru",
    "tempr.email", "discardmail.com", "discardmail.de", "mailbox52.ml", "mailbox92.biz",
    "fakemailgenerator.com", "burnermail.io", "incognitomail.com", "tempmailaddress.com",
    "luxusmail.org", "0-mail.com", "1secmail.com", "1secmail.net", "1secmail.org",
    "emailtemporanea.com", "emailtemporanea.net", "throwam.com", "tempemail.co",
    "deadaddress.com", "mailforspam.com", "mailnull.com", "no-spam.ws", "spam4.me",
    "armyspy.com", "cuvox.de", "dayrep.com", "einrot.com", "fleckens.hu", "gustr.com",
    "jourrapide.com", "rhyta.com", "superrito.com", "teleworm.us",
}

def is_disposable_email(email: str) -> bool:
    try:
        domain = email.rsplit("@", 1)[1].strip().lower()
    except IndexError:
        return False
    return domain in DISPOSABLE_EMAIL_DOMAINS

# ─────────────────────────────────────────────────────────
#  Utility — CSRF
# ─────────────────────────────────────────────────────────

def generate_csrf_token() -> str:
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return session["csrf_token"]

def verify_csrf(f):
    """Decorator: verifica X-CSRF-Token header per endpoint POST sensibili."""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("X-CSRF-Token", "")
        if not token or not secrets.compare_digest(token, session.get("csrf_token", "")):
            logger.warning("CSRF check fallito da IP %s", request.remote_addr)
            return jsonify({"ok": False, "error": "Token CSRF non valido"}), 403
        return f(*args, **kwargs)
    return decorated

def require_login(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login_page"))
        return f(*args, **kwargs)
    return decorated

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
    token = generate_csrf_token()
    return render_template("login.html", csrf_token=token)

@app.route("/leaderboard")
def leaderboard_page():
    if "user_id" not in session:
        return redirect(url_for("login_page"))
    return render_template("leaderboard.html")

@app.route("/profile")
@require_login
def profile_page():
    return render_template("profile.html")

# ─────────────────────────────────────────────────────────
#  API Auth
# ─────────────────────────────────────────────────────────

@app.route("/api/csrf_token")
def api_csrf_token():
    """Endpoint per ottenere il CSRF token corrente (usato dal frontend)."""
    return jsonify({"csrf_token": generate_csrf_token()})

@app.route("/api/register", methods=["POST"])
@limiter.limit("5 per minute; 20 per hour")   # anti-spam registrazione
def api_register():
    data     = request.get_json(force=True) or {}
    nome     = (data.get("nome",     "") or "").strip()
    cognome  = (data.get("cognome",  "") or "").strip()
    username = (data.get("username", "") or "").strip()
    email    = (data.get("email",    "") or "").strip().lower()
    password = data.get("password", "") or ""
    azienda       = (data.get("azienda",       "") or "").strip()
    compartimento = (data.get("compartimento", "") or "").strip()

    # Honeypot anti-bot: campo nascosto che solo i bot compilano
    honeypot = (data.get("website", "") or "").strip()
    if honeypot:
        logger.warning("Registrazione bloccata da honeypot per IP %s", request.remote_addr)
        # Risposta finta "ok" per non rivelare ai bot la presenza dell'honeypot
        return jsonify({"ok": True, "message": "Registrazione completata!"})

    captcha_token = data.get("captcha", "")
    if not captcha_token:
        return jsonify({"ok": False, "error": "Captcha mancante"}), 400

    if not RECAPTCHA_SECRET:
        logger.error("RECAPTCHA_SECRET non configurato nelle env var!")
        return jsonify({"ok": False, "error": "Configurazione server incompleta"}), 500

    import urllib.request as _ur, json as _json
    try:
        _resp = _ur.urlopen(
            f"https://www.google.com/recaptcha/api/siteverify"
            f"?secret={RECAPTCHA_SECRET}&response={captcha_token}",
            timeout=5
        )
        _rc = _json.loads(_resp.read())
        if not _rc.get("success"):
            return jsonify({"ok": False, "error": "Captcha non valido"}), 400
    except Exception:
        return jsonify({"ok": False, "error": "Errore verifica captcha"}), 500

    if not all([nome, cognome, username, email, password]):
        return jsonify({"ok": False, "error": "Tutti i campi sono obbligatori"}), 400
    if len(password) < 6:
        return jsonify({"ok": False, "error": "La password deve essere di almeno 6 caratteri"}), 400
    if not validate_email(email):
        return jsonify({"ok": False, "error": "Email non valida"}), 400
    if is_disposable_email(email):
        return jsonify({"ok": False, "error": "Indirizzi email temporanei/usa-e-getta non sono ammessi"}), 400
    if not validate_username(username):
        return jsonify({"ok": False, "error": "Username non valido (solo lettere, numeri, _, ., - ; 3-30 caratteri)"}), 400
    if not azienda or not compartimento:
        return jsonify({"ok": False, "error": "Azienda e Compartimento sono obbligatori"}), 400

    token = secrets.token_hex(32)
    try:
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO users (nome, cognome, username, email, password_hash, api_token, azienda, compartimento) "
                    "VALUES (%s,%s,%s,%s,%s,%s,%s,%s)",
                    (nome, cognome, username, email, hash_password(password), token, azienda, compartimento)
                )
            conn.commit()
        logger.info("Nuovo utente registrato: %s", username)
        return jsonify({"ok": True, "message": "Registrazione completata! Ora puoi accedere."})
    except psycopg2.errors.UniqueViolation as e:
        msg = str(e)
        if "username" in msg:
            return jsonify({"ok": False, "error": "Username già in uso"}), 409
        return jsonify({"ok": False, "error": "Email già registrata"}), 409


@app.route("/api/login", methods=["POST"])
@limiter.limit("10 per minute; 50 per hour")   # anti brute-force
def api_login():
    data     = request.get_json(force=True) or {}
    username = (data.get("username", "") or "").strip()
    password = data.get("password", "") or ""

    if not username or not password:
        return jsonify({"ok": False, "error": "Credenziali mancanti"}), 400

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT * FROM users WHERE (username=%s OR email=%s)",
                (username, username)
            )
            user = fetchone(cur)

    # Verifica password separata dall'interrogazione (evita timing oracle)
    if not user or not check_password(password, user["password_hash"]):
        logger.warning("Login fallito per '%s' da IP %s", username, request.remote_addr)
        return jsonify({"ok": False, "error": "Credenziali non valide"}), 401

    # Migra hash SHA-256 legacy → bcrypt se necessario
    migrate_password_if_needed(user["id"], password, user["password_hash"])

    session.permanent   = True
    session["user_id"]  = user["id"]
    session["username"] = user["username"]
    # Rigenera CSRF token ad ogni login
    session.pop("csrf_token", None)
    csrf = generate_csrf_token()

    logger.info("Login utente: %s da IP %s", user["username"], request.remote_addr)
    return jsonify({"ok": True, "username": user["username"], "csrf_token": csrf})

@app.route("/api/logout", methods=["POST"])
def api_logout():
    logger.info("Logout utente: %s", session.get("username", "?"))
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
        "azienda":       user.get("azienda") or "",
        "compartimento": user.get("compartimento") or "",
        "csrf_token": generate_csrf_token(),
    })

@app.route("/api/profile/extra", methods=["POST"])
@require_login
@verify_csrf
def api_profile_extra():
    data = request.get_json(silent=True) or {}
    azienda = (data.get("azienda") or "").strip()
    compartimento = (data.get("compartimento") or "").strip()
    with get_db() as conn:
        with conn.cursor() as cur:
            try:
                cur.execute(
                    "UPDATE users SET azienda=%s, compartimento=%s WHERE id=%s",
                    (azienda, compartimento, session["user_id"])
                )
            except Exception:
                conn.rollback()
                # Colonne mancanti: applica la migrazione e riprova
                with conn.cursor() as cur2:
                    cur2.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS azienda TEXT DEFAULT ''")
                    cur2.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS compartimento TEXT DEFAULT ''")
                conn.commit()
                with conn.cursor() as cur3:
                    cur3.execute(
                        "UPDATE users SET azienda=%s, compartimento=%s WHERE id=%s",
                        (azienda, compartimento, session["user_id"])
                    )
        conn.commit()
    return jsonify({"ok": True, "azienda": azienda, "compartimento": compartimento})

@app.route("/api/regenerate_token", methods=["POST"])
@require_login
@verify_csrf
def api_regenerate_token():
    """Permette all'utente di rigenerare il proprio api_token se compromesso."""
    new_token = secrets.token_hex(32)
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE users SET api_token=%s WHERE id=%s",
                (new_token, session["user_id"])
            )
        conn.commit()
    logger.info("API token rigenerato per user_id=%s", session["user_id"])
    return jsonify({"ok": True, "api_token": new_token})

# ─────────────────────────────────────────────────────────
#  API Leaderboard
# ─────────────────────────────────────────────────────────

@app.route("/api/leaderboard")
def api_leaderboard():
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT
                    u.id                              AS user_id,
                    u.username,
                    COALESCE(u.azienda, '')          AS azienda,
                    COALESCE(u.compartimento, '')    AS compartimento,
                    COALESCE(us.affidabilita, 0)    AS punteggio,
                    COALESCE(us.ultima_tratta, '')  AS ultimo_servizio,
                    COALESCE(us.grade, '')           AS grade,
                    COUNT(s.id)                      AS corse,
                    CASE
                        WHEN h.last_seen >= NOW() - INTERVAL '2 minutes'
                        THEN 1 ELSE 0
                    END                              AS online,
                    ls.speed_kmh,
                    ls.delay_min,
                    ls.next_station,
                    ls.consist,
                    ls.sim_time,
                    ls.activity_name,
                    ls.comfort_live
                FROM users u
                LEFT JOIN user_stats us ON us.user_id = u.id
                LEFT JOIN sessions s ON s.user_id = u.id
                LEFT JOIN heartbeats h ON h.user_id = u.id
                LEFT JOIN live_sessions ls ON ls.user_id = u.id
                WHERE us.affidabilita IS NOT NULL
                GROUP BY u.id, u.username, u.azienda, u.compartimento, us.affidabilita, us.ultima_tratta,
                         us.grade, h.last_seen, ls.speed_kmh, ls.delay_min,
                         ls.next_station, ls.consist, ls.sim_time,
                         ls.activity_name, ls.comfort_live
                ORDER BY us.affidabilita DESC
                LIMIT 100
            """)
            rows = fetchall(cur)

            # ── Badge in blocco per tutta la classifica ──
            cur.execute("""
                SELECT DISTINCT user_id, registrata_at::date AS giorno
                FROM sessions
            """)
            date_rows = fetchall(cur)
            primato_ids = _primato_user_ids(cur)

    days_by_user = defaultdict(set)
    for r in date_rows:
        days_by_user[r["user_id"]].add(r["giorno"])

    for row in rows:
        uid = row.pop("user_id")
        row["streak"] = _streak_for_days(days_by_user.get(uid, set()))
        row["has_primato"] = uid in primato_ids

    return jsonify(rows)

@app.route("/api/users/count")
def api_users_count():
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) AS count FROM users")
            row = fetchone(cur)
    return jsonify({"count": row["count"] if row else 0})

@app.route("/api/users")
def api_users():
    """Lista tutti gli utenti registrati con statistiche aggregate (pubblica, senza dati sensibili)."""
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT
                    u.username,
                    u.created_at::text                   AS created_at,
                    COALESCE(us.affidabilita, 0)         AS punteggio,
                    COALESCE(us.grade, '')               AS grade,
                    COUNT(s.id)                          AS corse,
                    CASE
                        WHEN h.last_seen >= NOW() - INTERVAL '2 minutes'
                        THEN 1 ELSE 0
                    END                                  AS online
                FROM users u
                LEFT JOIN user_stats us ON us.user_id = u.id
                LEFT JOIN sessions   s  ON s.user_id  = u.id
                LEFT JOIN heartbeats h  ON h.user_id  = u.id
                GROUP BY u.id, u.username, u.created_at,
                         us.affidabilita, us.grade, h.last_seen
                ORDER BY u.username ASC
            """)
            rows = fetchall(cur)
    return jsonify(rows)

@app.route("/api/my_sessions")
def api_my_sessions():
    if "user_id" not in session:
        return jsonify([]), 401
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

@app.route("/api/my_history")
def api_my_history():
    """Storico cronologico del punteggio dell'utente loggato, più la
    media generale della piattaforma per il confronto nel grafico."""
    if "user_id" not in session:
        return jsonify({"ok": False, "error": "Non autenticato"}), 401
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT punteggio, ultimo_servizio, grade,
                       registrata_at::text AS registrata_at
                FROM sessions WHERE user_id=%s
                ORDER BY registrata_at ASC LIMIT 50
            """, (session["user_id"],))
            rows = fetchall(cur)

            cur.execute("SELECT AVG(punteggio) AS avg FROM sessions")
            platform = fetchone(cur)

    platform_avg = float(platform["avg"]) if platform and platform["avg"] is not None else None
    return jsonify({"ok": True, "sessions": rows, "platform_avg": platform_avg})

@app.route("/api/user_sessions/<username>")
def api_user_sessions(username):
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM users WHERE username=%s", (username,))
            user = fetchone(cur)
    if not user:
        return jsonify([])
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT punteggio, ultimo_servizio, grade,
                       registrata_at::text AS registrata_at
                FROM sessions WHERE user_id=%s
                ORDER BY registrata_at DESC LIMIT 50
            """, (user["id"],))
            rows = fetchall(cur)
    return jsonify(rows)

@app.route("/api/badges/<username>")
def api_badges(username):
    """Badge calcolati al volo dai dati esistenti in 'sessions':
    streak di giorni consecutivi di guida e primati per linea."""
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM users WHERE username=%s", (username,))
            user = fetchone(cur)
    if not user:
        return jsonify({"ok": False, "error": "Utente non trovato"}), 404

    badges = []

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT DISTINCT registrata_at::date AS giorno
                FROM sessions WHERE user_id=%s
            """, (user["id"],))
            giorni = {r["giorno"] for r in fetchall(cur)}
            primati = _primati_for_user(cur, user["id"])

    streak = _streak_for_days(giorni)

    if streak >= 30:
        badges.append({"id": "streak_oro", "label": "Macchinista inarrestabile", "tier": "oro",
                        "desc": f"{streak} giorni consecutivi di guida"})
    elif streak >= 7:
        badges.append({"id": "streak_argento", "label": "Settimana in pista", "tier": "argento",
                        "desc": f"{streak} giorni consecutivi di guida"})
    elif streak >= 3:
        badges.append({"id": "streak_bronzo", "label": "Si comincia a scaldare", "tier": "bronzo",
                        "desc": f"{streak} giorni consecutivi di guida"})

    for p in primati:
        badges.append({
            "id": f"primato_{p['ultimo_servizio']}",
            "label": f"Record: {p['ultimo_servizio']}",
            "tier": "primato",
            "desc": f"Punteggio più alto su questa linea ({float(p['best']):.1f} pt)"
        })

    return jsonify({"ok": True, "username": username, "streak": streak, "badges": badges})

# ─────────────────────────────────────────────────────────
#  API ricezione dati dall'EXE
# ─────────────────────────────────────────────────────────

@app.route("/api/submit", methods=["POST"])
@limiter.limit("30 per minute")   # anti-spam submit sessioni
def api_submit():
    token = request.headers.get("X-API-Token", "").strip()
    if not token:
        return jsonify({"ok": False, "error": "Token mancante"}), 401
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM users WHERE api_token=%s", (token,))
            user = fetchone(cur)
    if not user:
        logger.warning("Submit con token non valido da IP %s", request.remote_addr)
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

    if completamento < 50:
        return jsonify({"ok": False, "error": f"Sessione troppo breve ({completamento}% < 50%)"}), 400

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO sessions
                  (user_id, punteggio, ultimo_servizio, frenate_brusche, accel_brusche,
                   penalita, completamento, durata_min, grade)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
            """, (user["id"], punteggio, ultimo_servizio, frenate, accel,
                  penalita, completamento, durata_min, grade))
            cur.execute("""
                INSERT INTO user_stats (user_id, affidabilita, ultima_tratta, grade, updated_at)
                SELECT
                    %s,
                    AVG(punteggio),
                    (SELECT ultimo_servizio FROM sessions
                     WHERE user_id=%s ORDER BY registrata_at DESC LIMIT 1),
                    (SELECT grade FROM sessions
                     WHERE user_id=%s ORDER BY registrata_at DESC LIMIT 1),
                    NOW()
                FROM sessions WHERE user_id=%s
                ON CONFLICT (user_id) DO UPDATE SET
                    affidabilita  = EXCLUDED.affidabilita,
                    ultima_tratta = EXCLUDED.ultima_tratta,
                    grade         = EXCLUDED.grade,
                    updated_at    = NOW()
            """, (user["id"], user["id"], user["id"], user["id"]))
        conn.commit()
    return jsonify({"ok": True, "message": "Sessione registrata!"})

# ─────────────────────────────────────────────────────────
#  API heartbeat (dal .exe, ogni 30s)
# ─────────────────────────────────────────────────────────

@app.route("/api/heartbeat", methods=["POST"])
@limiter.limit("120 per minute")   # max 2/s per utente
def api_heartbeat():
    token = request.headers.get("X-API-Token", "").strip()
    if not token:
        return jsonify({"ok": False, "error": "Token mancante"}), 401
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id, username FROM users WHERE api_token=%s", (token,))
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
    comfort_live    = float(data.get("comfort_live",    100) or 100)
    comfort_grade   = str(data.get("comfort_grade",    "")  or "")[:20]
    comfort_penalty = float(data.get("comfort_penalty",  0) or 0)
    train_lat       = float(data.get("train_lat", 0) or 0)
    train_lon       = float(data.get("train_lon", 0) or 0)
    train_dir       = float(data.get("train_dir", 0) or 0)

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT last_seen < NOW() - INTERVAL '2 minutes' AS was_offline
                FROM heartbeats WHERE user_id=%s
            """, (user["id"],))
            row = fetchone(cur)
            new_session = row is None or row["was_offline"]

            cur.execute("""
                INSERT INTO heartbeats (user_id, last_seen)
                VALUES (%s, NOW())
                ON CONFLICT (user_id) DO UPDATE SET last_seen = NOW()
            """, (user["id"],))
            cur.execute("""
                INSERT INTO live_sessions
                  (user_id, speed_kmh, delay_min, next_station, consist, sim_time, activity_name,
                   comfort_live, comfort_grade, comfort_penalty, train_lat, train_lon, train_dir, updated_at)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,NOW())
                ON CONFLICT (user_id) DO UPDATE SET
                  speed_kmh=EXCLUDED.speed_kmh,
                  delay_min=EXCLUDED.delay_min,
                  next_station=EXCLUDED.next_station,
                  consist=EXCLUDED.consist,
                  sim_time=EXCLUDED.sim_time,
                  activity_name=EXCLUDED.activity_name,
                  comfort_live=EXCLUDED.comfort_live,
                  comfort_grade=EXCLUDED.comfort_grade,
                  comfort_penalty=EXCLUDED.comfort_penalty,
                  train_lat=EXCLUDED.train_lat,
                  train_lon=EXCLUDED.train_lon,
                  train_dir=EXCLUDED.train_dir,
                  updated_at=NOW()
            """, (user["id"], speed_kmh, delay_min, next_station, consist, sim_time, activity_name,
                  comfort_live, comfort_grade, comfort_penalty, train_lat, train_lon, train_dir))
            if new_session:
                cur.execute("DELETE FROM speed_history WHERE user_id=%s", (user["id"],))
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

    if new_session:
        msg = f"🚆 **{user['username']}** è entrato in linea"
        if activity_name:
            msg += f" su *{activity_name}*"
        notify_discord(embed={
            "title": "Nuova sessione live",
            "description": msg,
            "color": 0x007A3D,
            "url": "https://" + request.host + "/leaderboard"
        })

    return jsonify({"ok": True})

# ─────────────────────────────────────────────────────────
#  API dati live
# ─────────────────────────────────────────────────────────

@app.route("/api/live")
def api_live():
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
                    ls.comfort_live,
                    ls.comfort_grade,
                    ls.comfort_penalty,
                    ls.train_lat,
                    ls.train_lon,
                    ls.train_dir,
                    ls.updated_at::text AS updated_at
                FROM live_sessions ls
                JOIN users u ON u.id = ls.user_id
                JOIN heartbeats h ON h.user_id = ls.user_id
                WHERE h.last_seen >= NOW() - INTERVAL '2 minutes'
                ORDER BY h.last_seen ASC
            """)
            users_online = fetchall(cur)

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
@limiter.limit("120 per minute")
def api_live_stations():
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
#  API eliminazione account
# ─────────────────────────────────────────────────────────

@app.route("/api/delete_account", methods=["POST"])
@require_login
@verify_csrf
def api_delete_account():
    data     = request.get_json(force=True) or {}
    password = data.get("password", "") or ""

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM users WHERE id=%s", (session["user_id"],))
            user = fetchone(cur)

    if not user or not check_password(password, user["password_hash"]):
        logger.warning("Tentativo eliminazione account fallito per user_id=%s", session["user_id"])
        return jsonify({"ok": False, "error": "Password non corretta"}), 401

    uid = session["user_id"]
    try:
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM speed_history   WHERE user_id=%s", (uid,))
                cur.execute("DELETE FROM live_stations   WHERE user_id=%s", (uid,))
                cur.execute("DELETE FROM live_sessions   WHERE user_id=%s", (uid,))
                cur.execute("DELETE FROM heartbeats      WHERE user_id=%s", (uid,))
                cur.execute("DELETE FROM sessions        WHERE user_id=%s", (uid,))
                cur.execute("DELETE FROM user_stats      WHERE user_id=%s", (uid,))
                cur.execute("DELETE FROM users           WHERE id=%s",      (uid,))
            conn.commit()
    except Exception as e:
        return jsonify({"ok": False, "error": f"Errore DB: {e}"}), 500

    logger.info("Account eliminato: user_id=%s", uid)
    session.clear()
    return jsonify({"ok": True, "message": "Account eliminato."})

# ─────────────────────────────────────────────────────────
#  API coordinate stazioni
# ─────────────────────────────────────────────────────────

@app.route("/api/station_coords", methods=["GET", "POST"])
def api_station_coords():
    if request.method == "GET":
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT name, lat, lon FROM station_coords ORDER BY name")
                rows = fetchall(cur)
        return jsonify({r["name"]: {"lat": r["lat"], "lon": r["lon"]} for r in rows})

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
    stations = data.get("stations", {})
    if not stations:
        return jsonify({"ok": False, "error": "Nessuna stazione"}), 400

    with get_db() as conn:
        with conn.cursor() as cur:
            for name, coords in stations.items():
                try:
                    lat = float(coords.get("lat", 0))
                    lon = float(coords.get("lon", 0))
                    if not (35.0 <= lat <= 47.5 and 6.0 <= lon <= 19.0):
                        continue
                    cur.execute("""
                        INSERT INTO station_coords (name, lat, lon, updated_at)
                        VALUES (%s, %s, %s, NOW())
                        ON CONFLICT (name) DO UPDATE SET
                            lat=EXCLUDED.lat, lon=EXCLUDED.lon, updated_at=NOW()
                    """, (str(name)[:100], lat, lon))
                except Exception:
                    pass
        conn.commit()
    return jsonify({"ok": True, "count": len(stations)})

# ─────────────────────────────────────────────────────────
#  API riepilogo Discord (chiamata da cron esterno)
# ─────────────────────────────────────────────────────────

@app.route("/api/discord/daily_summary", methods=["POST"])
def api_discord_daily_summary():
    """Posta su Discord la top 10 classifica corrente.
    Protetto da header X-Cron-Token, da chiamare con un cron esterno
    (es. cron-job.org, GitHub Actions scheduled workflow)."""
    token = request.headers.get("X-Cron-Token", "")
    if not DISCORD_CRON_SECRET or not secrets.compare_digest(token, DISCORD_CRON_SECRET):
        return jsonify({"ok": False, "error": "Non autorizzato"}), 401

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT u.username,
                       COALESCE(us.affidabilita, 0) AS punteggio,
                       COALESCE(us.grade, '')        AS grade
                FROM users u
                JOIN user_stats us ON us.user_id = u.id
                WHERE us.affidabilita IS NOT NULL
                ORDER BY us.affidabilita DESC
                LIMIT 10
            """)
            top = fetchall(cur)

    if not top:
        notify_discord(content="📊 Nessun dato per il riepilogo di oggi.")
        return jsonify({"ok": True})

    medals = ["🥇", "🥈", "🥉"]
    lines = []
    for i, row in enumerate(top):
        prefix = medals[i] if i < 3 else f"{i + 1}."
        lines.append(f"{prefix} **{row['username']}** — {row['punteggio']:.1f} pt ({row['grade'] or '—'})")

    notify_discord(embed={
        "title": "📊 Classifica — Riepilogo",
        "description": "\n".join(lines),
        "color": 0xCE1B26,
        "url": "https://" + request.host + "/leaderboard"
    })
    return jsonify({"ok": True, "count": len(top)})

# ─────────────────────────────────────────────────────────

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
