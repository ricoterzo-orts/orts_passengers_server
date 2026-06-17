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
import psycopg2, psycopg2.extras, psycopg2.errorcodes, psycopg2.pool
import os, secrets, re, logging, threading, time
from contextlib import contextmanager

import bcrypt
import requests
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from datetime import timedelta, datetime, timezone
from authlib.integrations.flask_client import OAuth
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# ─────────────────────────────────────────────────────────
#  App setup
# ─────────────────────────────────────────────────────────

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))

app.config["SESSION_COOKIE_SECURE"]   = True   # ← era False, CORRETTO
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"   # era "Strict", necessario per OAuth redirect
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=30)

# ─────────────────────────────────────────────────────────
#  OAuth2 — Google e Discord
# ─────────────────────────────────────────────────────────

oauth = OAuth(app)

oauth.register(
    name='google',
    client_id=os.environ.get('GOOGLE_CLIENT_ID', ''),
    client_secret=os.environ.get('GOOGLE_CLIENT_SECRET', ''),
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'}
)

oauth.register(
    name='discord',
    client_id=os.environ.get('DISCORD_CLIENT_ID', ''),
    client_secret=os.environ.get('DISCORD_CLIENT_SECRET', ''),
    access_token_url='https://discord.com/api/oauth2/token',
    authorize_url='https://discord.com/api/oauth2/authorize',
    api_base_url='https://discord.com/',
    client_kwargs={'scope': 'identify email'}
)

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

# ─────────────────────────────────────────────────────────
#  Email SMTP (per reset password)
# ─────────────────────────────────────────────────────────

SMTP_HOST     = os.environ.get("SMTP_HOST", "")
SMTP_PORT     = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER     = os.environ.get("SMTP_USER", "")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")
SMTP_FROM     = os.environ.get("SMTP_FROM", SMTP_USER)
APP_BASE_URL  = os.environ.get("APP_BASE_URL", "https://orts-passengers-server.onrender.com")

def send_email(to_address: str, subject: str, body_html: str) -> bool:
    """Invia un'email via SMTP. Ritorna True se l'invio ha successo."""
    if not all([SMTP_HOST, SMTP_USER, SMTP_PASSWORD]):
        logger.warning("SMTP non configurato: impossibile inviare email a %s", to_address)
        return False
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"]    = SMTP_FROM
        msg["To"]      = to_address
        msg.attach(MIMEText(body_html, "html", "utf-8"))
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as smtp:
            smtp.ehlo()
            smtp.starttls()
            smtp.login(SMTP_USER, SMTP_PASSWORD)
            smtp.sendmail(SMTP_FROM, [to_address], msg.as_string())
        logger.info("Email inviata a %s — oggetto: %s", to_address, subject)
        return True
    except Exception:
        logger.exception("Errore invio email a %s", to_address)
        return False

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

def _create_pool_with_retry(
    dsn: str,
    minconn: int = 1,
    maxconn: int = 8,
    delays: tuple = (2, 4, 8, 16, 32),
) -> psycopg2.pool.ThreadedConnectionPool:
    """
    Crea il ThreadedConnectionPool con retry esponenziale.

    Un blip momentaneo al boot (pooler che si sveglia, network glitch,
    circuit breaker Supabase) non causa più un crash immediato: il processo
    ritenta fino a len(delays) volte prima di arrendersi — evitando il
    crash-loop su Render.

    delays: sequenza di secondi di attesa tra un tentativo e il successivo.
            Default: 2 → 4 → 8 → 16 → 32 s  (totale max ~62 s di attesa).
    """
    last_exc: Exception | None = None
    for attempt, wait in enumerate(delays, start=1):
        try:
            pool = psycopg2.pool.ThreadedConnectionPool(
                minconn=minconn,
                maxconn=maxconn,
                dsn=dsn,
            )
            if attempt > 1:
                logger.info("DB pool creato al tentativo %d.", attempt)
            return pool
        except Exception as exc:
            last_exc = exc
            logger.warning(
                "Impossibile creare il DB pool (tentativo %d/%d): %s — "
                "nuovo tentativo tra %ds…",
                attempt, len(delays), exc, wait,
            )
            time.sleep(wait)

    # Tutti i tentativi esauriti: crash esplicito con log chiaro
    logger.critical(
        "DB pool non creato dopo %d tentativi. Arresto del processo.",
        len(delays),
    )
    raise RuntimeError(
        f"Impossibile connettersi al database dopo {len(delays)} tentativi."
    ) from last_exc


db_pool = _create_pool_with_retry(
    dsn=DATABASE_URL,
    minconn=1,
    maxconn=int(os.environ.get("DB_POOL_MAX", "8")),
)

@contextmanager
def get_db():
    """
    Ritorna una connessione presa dal pool (NON ne apre una nuova ogni volta).
    Al termine del blocco 'with' la connessione viene fatta commit/rollback
    e restituita al pool — mai chiusa, mai 'persa'.

    NB: prima, get_db() faceva psycopg2.connect(...) ad ogni chiamata e
    'with conn:' su psycopg2 NON chiude la connessione (gestisce solo la
    transazione), quindi ogni richiesta API lasciava una connessione TCP
    aperta verso Postgres/Supabase fino al garbage collector. Con /api/live
    che apriva 1 + N connessioni (N = utenti online) ad ogni poll dei
    client, con 2+ utenti live il pool del pooler Supabase si esauriva
    rapidamente e le richieste iniziavano a fallire silenziosamente.
    """
    conn = db_pool.getconn()
    # Scarta connessioni "morte" (es. chiuse per inattività dal pooler
    # Supabase): senza questo controllo verrebbe restituito un errore al
    # primo utilizzo, e quella connessione resterebbe bloccata nel pool.
    if conn.closed:
        db_pool.putconn(conn, close=True)
        conn = db_pool.getconn()

    ok = True
    try:
        yield conn
        conn.commit()
    except psycopg2.OperationalError:
        # Connessione caduta durante l'uso: non rimetterla nel pool,
        # la prossima getconn() ne aprirà una nuova.
        ok = False
        raise
    except Exception:
        conn.rollback()
        raise
    finally:
        db_pool.putconn(conn, close=not ok)

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
            CREATE TABLE IF NOT EXISTS password_reset_tokens (
                id          SERIAL PRIMARY KEY,
                user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                token       TEXT    NOT NULL UNIQUE,
                expires_at  TIMESTAMPTZ NOT NULL,
                used        BOOLEAN DEFAULT FALSE,
                created_at  TIMESTAMPTZ DEFAULT NOW()
            );
            CREATE TABLE IF NOT EXISTS user_stats_period (
                user_id      INTEGER NOT NULL REFERENCES users(id),
                period       TEXT    NOT NULL,
                period_key   TEXT    NOT NULL,
                affidabilita REAL    DEFAULT 0,
                corse        INTEGER DEFAULT 0,
                ultima_tratta TEXT   DEFAULT '',
                grade        TEXT    DEFAULT '',
                updated_at   TIMESTAMPTZ DEFAULT NOW(),
                PRIMARY KEY (user_id, period, period_key)
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
        """ALTER TABLE users ADD COLUMN IF NOT EXISTS google_id TEXT""",
        """ALTER TABLE users ADD COLUMN IF NOT EXISTS discord_id TEXT""",
        # password_hash diventa nullable per utenti OAuth (non hanno password)
        """ALTER TABLE users ALTER COLUMN password_hash SET DEFAULT ''""",
        """CREATE TABLE IF NOT EXISTS password_reset_tokens (
            id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            token TEXT NOT NULL UNIQUE,
            expires_at TIMESTAMPTZ NOT NULL,
            used BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMPTZ DEFAULT NOW()
        )""",
        """CREATE TABLE IF NOT EXISTS user_stats_period (
            user_id      INTEGER NOT NULL REFERENCES users(id),
            period       TEXT    NOT NULL,
            period_key   TEXT    NOT NULL,
            affidabilita REAL    DEFAULT 0,
            corse        INTEGER DEFAULT 0,
            ultima_tratta TEXT   DEFAULT '',
            grade        TEXT    DEFAULT '',
            updated_at   TIMESTAMPTZ DEFAULT NOW(),
            PRIMARY KEY (user_id, period, period_key)
        )""",
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
    Supporta anche hash SHA-256 legacy per utenti pre-migrazione.
    Utenti OAuth hanno password_hash vuoto: per loro il login classico
    è sempre negato, indipendentemente dalla password inserita."""
    if not hashed:
        return False
    try:
        # Tenta verifica bcrypt (nuovo formato)
        return bcrypt.checkpw(pw.encode(), hashed.encode())
    except Exception:
        # Fallback: confronto SHA-256 legacy (da rimuovere dopo migrazione completa)
        import hashlib
        return hashlib.sha256(pw.encode()).hexdigest() == hashed

def migrate_password_if_needed(user_id: int, password: str, stored_hash: str) -> None:
    """Se l'hash è ancora nel vecchio formato SHA-256 (non bcrypt),
    lo rigenera in bcrypt dopo un login riuscito. Migrazione 'lazy',
    un utente alla volta, senza toccare gli altri."""
    if stored_hash and not stored_hash.startswith(("$2a$", "$2b$", "$2y$")):
        new_hash = hash_password(password)
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("UPDATE users SET password_hash=%s WHERE id=%s", (new_hash, user_id))
            conn.commit()
        logger.info("Password migrata a bcrypt per user_id=%s", user_id)

def _oauth_login_or_create(provider: str, provider_id: str, email: str,
                            nome: str, cognome: str) -> dict:
    """
    Cerca l'utente per provider_id o email.
    Se non esiste lo crea con password vuota (non può fare login classico).
    Restituisce il record utente.
    """
    id_col = f"{provider}_id"   # 'google_id' o 'discord_id'

    with get_db() as conn:
        with conn.cursor() as cur:
            # Prima cerca per provider ID
            cur.execute(f"SELECT * FROM users WHERE {id_col}=%s", (provider_id,))
            user = fetchone(cur)
            if not user and email:
                # Poi per email (utente già registrato con metodo classico)
                cur.execute("SELECT * FROM users WHERE email=%s", (email,))
                user = fetchone(cur)

            if user:
                # Collega il provider_id se mancava (es. stesso utente, prima volta OAuth)
                if not user.get(id_col):
                    cur.execute(
                        f"UPDATE users SET {id_col}=%s WHERE id=%s",
                        (provider_id, user["id"])
                    )
                return user

            # Crea nuovo utente OAuth
            username_base = (email.split("@")[0] if email else f"{provider}_{provider_id[:8]}")
            username_base = re.sub(r"[^a-zA-Z0-9_.\-]", "_", username_base)[:28]
            username = username_base
            suffix = 1
            while True:
                cur.execute("SELECT id FROM users WHERE username=%s", (username,))
                if not cur.fetchone():
                    break
                username = f"{username_base}_{suffix}"
                suffix += 1

            api_token = secrets.token_hex(32)
            cur.execute(
                f"""INSERT INTO users
                    (nome, cognome, username, email, password_hash, api_token, {id_col})
                    VALUES (%s,%s,%s,%s,%s,%s,%s)
                    RETURNING *""",
                (nome or username, cognome or "", username,
                 email or "", "", api_token, provider_id)
            )
            user = fetchone(cur)
            # Crea riga user_stats
            cur.execute(
                "INSERT INTO user_stats (user_id) VALUES (%s) ON CONFLICT DO NOTHING",
                (user["id"],)
            )
            logger.info("Nuovo utente OAuth (%s) creato: %s", provider, username)
            notify_discord(content=f"🆕 Nuovo utente via {provider.capitalize()}: **{username}**")
            return user

# ─────────────────────────────────────────────────────────
#  Utility — Validazione
# ─────────────────────────────────────────────────────────

def validate_email(email: str) -> bool:
    return bool(re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email))

def validate_username(username: str) -> bool:
    """Solo lettere, numeri, underscore, punto, trattino. Lunghezza 3-30."""
    return bool(re.match(r"^[a-zA-Z0-9_.\-]{3,30}$", username))

# ─────────────────────────────────────────────────────────
#  Utility — Periodi classifica (settimanale/mensile)
# ─────────────────────────────────────────────────────────

def current_week_key() -> str:
    """Es. '2026-W24' — ISO week, si resetta ogni lunedì."""
    iso = __import__("datetime").datetime.utcnow().isocalendar()
    return f"{iso[0]}-W{iso[1]:02d}"

def current_month_key() -> str:
    """Es. '2026-06' — si resetta il primo giorno del mese."""
    return __import__("datetime").datetime.utcnow().strftime("%Y-%m")

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

@app.route("/completa-profilo")
@require_login
def complete_profile_page():
    token = generate_csrf_token()
    return render_template("complete_profile.html", csrf_token=token)

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

    token = secrets.token_hex(32)
    try:
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO users (nome, cognome, username, email, password_hash, api_token, azienda, compartimento) "
                    "VALUES (%s,%s,%s,%s,%s,%s,%s,%s)",
                    (nome, cognome, username, email, hash_password(password), token, '', '')
                )
            conn.commit()
        logger.info("Nuovo utente registrato: %s", username)
        return jsonify({"ok": True, "redirect_to": "/completa-profilo"})
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
    profile_complete = bool(user.get("azienda") and user.get("compartimento"))
    redirect_to = "/leaderboard" if profile_complete else "/completa-profilo"
    return jsonify({"ok": True, "username": user["username"], "csrf_token": csrf, "redirect_to": redirect_to})

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
#  OAuth2 — Google
# ─────────────────────────────────────────────────────────

@app.route("/auth/google")
def auth_google():
    redirect_uri = url_for("auth_google_callback", _external=True)
    return oauth.google.authorize_redirect(redirect_uri)

@app.route("/auth/google/callback")
def auth_google_callback():
    try:
        token = oauth.google.authorize_access_token()
        info  = token.get("userinfo") or oauth.google.userinfo(token=token)
        provider_id = str(info["sub"])
        email       = (info.get("email") or "").lower()
        nome        = info.get("given_name", "")
        cognome     = info.get("family_name", "")
    except Exception as e:
        logger.warning("Google OAuth callback error: %s", e)
        return redirect(url_for("login_page") + "?oauth_error=google")

    user = _oauth_login_or_create("google", provider_id, email, nome, cognome)
    session.permanent  = True
    session["user_id"] = user["id"]
    session["username"]= user["username"]
    session.pop("csrf_token", None)
    generate_csrf_token()
    if not (user.get("azienda") and user.get("compartimento")):
        return redirect(url_for("complete_profile_page"))
    return redirect(url_for("leaderboard_page"))

# ─────────────────────────────────────────────────────────
#  OAuth2 — Discord
# ─────────────────────────────────────────────────────────

@app.route("/auth/discord")
def auth_discord():
    redirect_uri = url_for("auth_discord_callback", _external=True)
    return oauth.discord.authorize_redirect(redirect_uri)

@app.route("/auth/discord/callback")
def auth_discord_callback():
    try:
        oauth.discord.authorize_access_token()
        resp = oauth.discord.get("api/users/@me")
        info = resp.json()
        provider_id = str(info["id"])
        email       = (info.get("email") or "").lower()
        username_dc = info.get("username", "")
        nome        = username_dc
        cognome     = ""
    except Exception as e:
        logger.warning("Discord OAuth callback error: %s", e)
        return redirect(url_for("login_page") + "?oauth_error=discord")

    user = _oauth_login_or_create("discord", provider_id, email, nome, cognome)
    session.permanent  = True
    session["user_id"] = user["id"]
    session["username"]= user["username"]
    session.pop("csrf_token", None)
    generate_csrf_token()
    if not (user.get("azienda") and user.get("compartimento")):
        return redirect(url_for("complete_profile_page"))
    return redirect(url_for("leaderboard_page"))

# ─────────────────────────────────────────────────────────
#  API Leaderboard
# ─────────────────────────────────────────────────────────

@app.route("/api/leaderboard")
def api_leaderboard():
    """Classifica generale (default, mai si resetta), oppure settimanale/mensile
    tramite il parametro ?period=week|month. La classifica generale resta
    sempre basata sulla affidabilita' cumulativa in user_stats."""
    period = request.args.get("period", "all").strip().lower()

    if period == "week":
        period_key = current_week_key()
    elif period == "month":
        period_key = current_month_key()
    else:
        period = "all"
        period_key = None

    with get_db() as conn:
        with conn.cursor() as cur:
            if period == "all":
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
            else:
                cur.execute("""
                    SELECT
                        u.id                              AS user_id,
                        u.username,
                        COALESCE(u.azienda, '')          AS azienda,
                        COALESCE(u.compartimento, '')    AS compartimento,
                        COALESCE(usp.affidabilita, 0)   AS punteggio,
                        COALESCE(usp.ultima_tratta, '') AS ultimo_servizio,
                        COALESCE(usp.grade, '')          AS grade,
                        COALESCE(usp.corse, 0)           AS corse,
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
                    JOIN user_stats_period usp ON usp.user_id = u.id
                        AND usp.period = %s AND usp.period_key = %s
                    LEFT JOIN heartbeats h ON h.user_id = u.id
                    LEFT JOIN live_sessions ls ON ls.user_id = u.id
                    ORDER BY usp.affidabilita DESC
                    LIMIT 100
                """, (period, period_key))
            rows = fetchall(cur)

    for row in rows:
        row.pop("user_id", None)

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

            # Aggiorna le classifiche periodiche (settimanale / mensile)
            for period, period_key in (("week", current_week_key()), ("month", current_month_key())):
                cur.execute("""
                    INSERT INTO user_stats_period
                      (user_id, period, period_key, affidabilita, corse, ultima_tratta, grade, updated_at)
                    VALUES (%s, %s, %s, %s, 1, %s, %s, NOW())
                    ON CONFLICT (user_id, period, period_key) DO UPDATE SET
                        affidabilita  = (user_stats_period.affidabilita * user_stats_period.corse + %s)
                                         / (user_stats_period.corse + 1),
                        corse         = user_stats_period.corse + 1,
                        ultima_tratta = %s,
                        grade         = %s,
                        updated_at    = NOW()
                """, (user["id"], period, period_key, punteggio, ultimo_servizio, grade,
                      punteggio, ultimo_servizio, grade))
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
        msg = f"🚆 **{user['username']}** è in servizio"
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

def _fetch_live_data():
    """Esegue le query reali per /api/live (3 query batch, 1 sola connessione)."""
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

            if not users_online:
                return []

            user_ids = [u["user_id"] for u in users_online]

            # Storico velocità per TUTTI gli utenti online in un'unica query
            cur.execute("""
                SELECT user_id, speed_kmh, sim_time, recorded_at::text AS recorded_at
                FROM speed_history
                WHERE user_id = ANY(%s)
                ORDER BY user_id, recorded_at DESC
            """, (user_ids,))
            history_rows = fetchall(cur)

            # Fermate per TUTTI gli utenti online in un'unica query
            cur.execute("""
                SELECT user_id, station_name, arrival, departure, delay_min,
                       passed, is_current, sort_order
                FROM live_stations
                WHERE user_id = ANY(%s)
                ORDER BY user_id, sort_order ASC
            """, (user_ids,))
            station_rows = fetchall(cur)

    # Raggruppa storico velocità per utente (max 40 punti, ordine cronologico)
    history_by_user = {}
    for row in history_rows:
        lst = history_by_user.setdefault(row["user_id"], [])
        if len(lst) < 40:
            lst.append(row)
    for lst in history_by_user.values():
        lst.reverse()

    # Raggruppa fermate per utente
    stations_by_user = {}
    for row in station_rows:
        stations_by_user.setdefault(row["user_id"], []).append(row)

    for u in users_online:
        u["speed_history"] = history_by_user.get(u["user_id"], [])
        u["stations"] = stations_by_user.get(u["user_id"], [])

    return users_online


# ── Cache in memoria per /api/live ──────────────────────────────────────
# I client (ognuno dei quali può avere la pagina leaderboard aperta) fanno
# polling di /api/live ogni 5s. Prima, OGNI poll di OGNI client generava
# query dirette al DB (e con l'N+1 di prima, 1+N connessioni per poll).
# Con N client connessi e M treni live il carico cresceva come N*M.
#
# Ora un singolo thread di background interroga il DB ogni
# LIVE_CACHE_INTERVAL secondi e tiene il risultato in memoria; tutte le
# richieste /api/live leggono semplicemente questa cache, quindi il carico
# sul DB non dipende più dal numero di client connessi (resta O(1) per
# processo worker). Se la cache è vuota o troppo vecchia (es. il thread
# non è ancora partito, o gunicorn è in modalità --preload), la route fa
# comunque un fetch diretto come fallback "self-healing".
LIVE_CACHE_INTERVAL = float(os.environ.get("LIVE_CACHE_INTERVAL", "3"))
LIVE_CACHE_MAX_AGE  = float(os.environ.get("LIVE_CACHE_MAX_AGE", "15"))

_live_cache_lock = threading.Lock()
_live_cache = {"data": [], "updated": 0.0}


def _live_cache_loop():
    while True:
        try:
            data = _fetch_live_data()
            with _live_cache_lock:
                _live_cache["data"] = data
                _live_cache["updated"] = time.time()
        except Exception:
            logger.exception("Errore aggiornamento cache /api/live")
        time.sleep(LIVE_CACHE_INTERVAL)


threading.Thread(target=_live_cache_loop, daemon=True).start()


@app.route("/api/live")
def api_live():
    with _live_cache_lock:
        data = _live_cache["data"]
        age = time.time() - _live_cache["updated"]

    if age > LIVE_CACHE_MAX_AGE:
        try:
            data = _fetch_live_data()
            with _live_cache_lock:
                _live_cache["data"] = data
                _live_cache["updated"] = time.time()
        except Exception:
            logger.exception("Fallback diretto /api/live fallito")

    return jsonify(data)

def _norm_station_name(name):
    """Normalizza il nome stazione per il confronto di deduplica."""
    return str(name or "").strip().casefold()


def _dedupe_stations(stations):
    """Unisce fermate consecutive con lo stesso nome (es. doppio PlatformItem
    per binari/direzioni diverse) in una sola riga, mantenendo i dati piu'
    completi tra le due (arrivo/partenza/ritardo/stato)."""
    result = []
    for st in stations:
        name = _norm_station_name(st.get("name"))
        if result and _norm_station_name(result[-1].get("name")) == name:
            prev = result[-1]
            # arrivo/partenza: tieni il valore non vuoto
            if not str(prev.get("arrival", "") or "").strip():
                prev["arrival"] = st.get("arrival", "")
            if not str(prev.get("departure", "") or "").strip():
                prev["departure"] = st.get("departure", "")
            # stato: basta che una delle due righe sia passata/corrente
            prev["passed"] = bool(prev.get("passed")) or bool(st.get("passed"))
            prev["is_current"] = bool(prev.get("is_current")) or bool(st.get("is_current"))
            # ritardo: tieni il valore non nullo/non zero piu' significativo
            prev_delay = prev.get("delay_min", 0) or 0
            cur_delay = st.get("delay_min", 0) or 0
            if abs(float(cur_delay)) > abs(float(prev_delay)):
                prev["delay_min"] = cur_delay
            continue
        result.append(dict(st))
    return result


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
    stations = _dedupe_stations(data.get("stations", []))

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
                cur.execute("DELETE FROM user_stats        WHERE user_id=%s", (uid,))
                cur.execute("DELETE FROM user_stats_period WHERE user_id=%s", (uid,))
                cur.execute("DELETE FROM users             WHERE id=%s",      (uid,))
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
#  API recupero password
# ─────────────────────────────────────────────────────────

@app.route("/api/password_reset_request", methods=["POST"])
@limiter.limit("5 per hour")   # anti-spam: max 5 richieste/ora per IP
def api_password_reset_request():
    """Genera un token di reset e invia l'email. Non rivela mai se l'email esiste."""
    data  = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()

    if not email:
        # Risposta generica per non rivelare nulla
        return jsonify({"ok": True})

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id, username FROM users WHERE LOWER(email)=%s", (email,))
            user = fetchone(cur)

    if user:
        token      = secrets.token_urlsafe(48)
        expires_at = datetime.now(timezone.utc) + timedelta(hours=2)

        with get_db() as conn:
            with conn.cursor() as cur:
                # Invalida eventuali token precedenti non ancora usati
                cur.execute(
                    "UPDATE password_reset_tokens SET used=TRUE WHERE user_id=%s AND used=FALSE",
                    (user["id"],)
                )
                cur.execute(
                    """INSERT INTO password_reset_tokens (user_id, token, expires_at)
                       VALUES (%s, %s, %s)""",
                    (user["id"], token, expires_at)
                )
            conn.commit()

        reset_url = f"{APP_BASE_URL}/reset-password?token={token}"
        body = f"""
        <html><body style="font-family:'Trebuchet MS',sans-serif;color:#2B2B2B;max-width:480px;margin:auto;padding:24px">
          <img src="{APP_BASE_URL}/static/VTV_logo.jpg" alt="ViaggiaTreno Virtual" style="max-width:140px;margin-bottom:20px">
          <h2 style="font-size:14px;letter-spacing:.08em;text-transform:uppercase;color:#CE1B26;margin-bottom:12px">
            Recupero Password
          </h2>
          <p style="font-size:13px;line-height:1.7;margin-bottom:16px">
            Ciao <strong>{user["username"]}</strong>,<br>
            hai richiesto il reset della password per il tuo account ViaggiaTreno Virtual.<br>
            Clicca il pulsante qui sotto per impostare una nuova password.
            Il link è valido per <strong>2 ore</strong>.
          </p>
          <a href="{reset_url}"
             style="display:inline-block;background:#CE1B26;color:#fff;text-decoration:none;
                    padding:12px 28px;border-radius:2px;font-size:12px;font-weight:500;
                    letter-spacing:.08em;text-transform:uppercase">
            Reimposta password
          </a>
          <p style="font-size:11px;color:#888;margin-top:20px;line-height:1.6">
            Se non hai richiesto questo reset, ignora questa email: il tuo account è al sicuro.<br>
            Link diretto: <a href="{reset_url}" style="color:#CE1B26">{reset_url}</a>
          </p>
          <hr style="border:none;border-top:1px solid #eee;margin:24px 0">
          <p style="font-size:10px;color:#aaa">ViaggiaTreno Virtual — TSH Studio Repaint</p>
        </body></html>
        """
        send_email(email, "ViaggiaTreno Virtual — Recupero password", body)
        logger.info("Reset password richiesto per user_id=%s", user["id"])

    # Risposta sempre identica (non rivela se l'email è registrata)
    return jsonify({"ok": True})


@app.route("/reset-password")
def reset_password_page():
    """Pagina di reset password (token via query string)."""
    token = request.args.get("token", "").strip()
    # Verifica subito che il token esista e non sia scaduto/usato
    valid = False
    if token:
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT id FROM password_reset_tokens
                    WHERE token=%s AND used=FALSE AND expires_at > NOW()
                """, (token,))
                valid = bool(fetchone(cur))
    return render_template("reset_password.html", token=token, valid=valid)


@app.route("/api/password_reset_confirm", methods=["POST"])
@limiter.limit("10 per hour")
def api_password_reset_confirm():
    """Imposta la nuova password tramite token di reset."""
    data         = request.get_json(silent=True) or {}
    token        = (data.get("token") or "").strip()
    new_password = data.get("password", "") or ""

    if not token or not new_password:
        return jsonify({"ok": False, "error": "Dati mancanti"}), 400
    if len(new_password) < 6:
        return jsonify({"ok": False, "error": "La password deve essere di almeno 6 caratteri"}), 400

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT prt.id AS token_id, prt.user_id
                FROM password_reset_tokens prt
                WHERE prt.token=%s AND prt.used=FALSE AND prt.expires_at > NOW()
            """, (token,))
            row = fetchone(cur)

    if not row:
        return jsonify({"ok": False, "error": "Link non valido o scaduto. Richiedi un nuovo reset."}), 400

    new_hash = hash_password(new_password)
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE users SET password_hash=%s WHERE id=%s", (new_hash, row["user_id"]))
            cur.execute("UPDATE password_reset_tokens SET used=TRUE WHERE id=%s", (row["token_id"],))
        conn.commit()

    logger.info("Password reimpostata per user_id=%s", row["user_id"])
    return jsonify({"ok": True, "message": "Password aggiornata con successo. Ora puoi accedere."})


# ─────────────────────────────────────────────────────────

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
