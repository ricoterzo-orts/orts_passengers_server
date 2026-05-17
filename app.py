from flask import Flask, request, jsonify, render_template, session, redirect, url_for
import psycopg2, psycopg2.extras
import hashlib, os, secrets

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))
DATABASE_URL = os.environ.get("DATABASE_URL", "")

def get_db():
    return psycopg2.connect(DATABASE_URL)

def fetchone(cur):
    row = cur.fetchone()
    if row is None: return None
    cols = [d[0] for d in cur.description]
    return dict(zip(cols, row))

def fetchall(cur):
    cols = [d[0] for d in cur.description]
    return [dict(zip(cols, row)) for row in cur.fetchall()]

@app.route("/")
def index():
    if "user_id" not in session: return redirect(url_for("login_page"))
    return render_template("leaderboard.html")

@app.route("/login")
def login_page():
    if "user_id" in session: return redirect(url_for("index"))
    return render_template("login.html")

@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.json
    u, p = data.get("username", "").strip(), data.get("password", "")
    phash = hashlib.sha256(p.encode()).hexdigest()
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id, username FROM users WHERE (username=%s OR email=%s) AND password_hash=%s", (u, u, phash))
            user = fetchone(cur)
    if user:
        session.permanent = True
        session["user_id"] = user["id"]
        session["username"] = user["username"]
        return jsonify({"ok": True})
    return jsonify({"ok": False, "error": "Credenziali errate"})

@app.route("/api/submit_session", methods=["POST"])
def submit_session():
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM users WHERE api_token=%s", (token,))
            user = fetchone(cur)
            if not user: return jsonify({"ok": False, "error": "Token non valido"}), 401
            d = request.json
            cur.execute("INSERT INTO sessions (user_id, punteggio, ultimo_servizio, grade, durata_min, registrata_at) VALUES (%s, %s, %s, %s, %s, NOW())", 
                        (user['id'], d.get('punteggio'), d.get('ultimo_servizio'), d.get('grade'), d.get('durata_min')))
        conn.commit()
    return jsonify({"ok": True})

@app.route("/api/live_update", methods=["POST"])
def live_update():
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM users WHERE api_token=%s", (token,))
            user = fetchone(cur)
            if not user: return jsonify({"ok": False, "error": "Token non valido"}), 401
            d = request.json
            cur.execute("INSERT INTO live_trains (user_id, lat, lon, speed_kmh, delay_min, activity_name, updated_at) VALUES (%s, %s, %s, %s, %s, %s, NOW()) ON CONFLICT (user_id) DO UPDATE SET lat=EXCLUDED.lat, lon=EXCLUDED.lon, speed_kmh=EXCLUDED.speed_kmh, delay_min=EXCLUDED.delay_min, activity_name=EXCLUDED.activity_name, updated_at=NOW()",
                        (user['id'], d.get('lat'), d.get('lon'), d.get('speed_kmh'), d.get('delay_min'), d.get('activity_name')))
        conn.commit()
    return jsonify({"ok": True})

@app.route("/api/leaderboard")
def api_lb():
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT u.username, MAX(s.punteggio) as punteggio, (SELECT ultimo_servizio FROM sessions WHERE user_id=u.id ORDER BY registrata_at DESC LIMIT 1) as ultimo_servizio, EXISTS(SELECT 1 FROM live_trains WHERE user_id=u.id AND updated_at > NOW() - INTERVAL '1 minute') as online FROM users u JOIN sessions s ON u.id = s.user_id GROUP BY u.id, u.username ORDER BY punteggio DESC")
            return jsonify(fetchall(cur))

@app.route("/api/live")
def api_live():
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT l.*, u.username FROM live_trains l JOIN users u ON l.user_id=u.id WHERE updated_at > NOW() - INTERVAL '2 minutes'")
            return jsonify(fetchall(cur))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
