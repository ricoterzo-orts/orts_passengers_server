"""
OpenRails Monitor — Piattaforma Web v1.1
Backend Flask con PostgreSQL (persistente su Render)
"""

from flask import Flask, request, jsonify, render_template, session, redirect, url_for
from functools import wraps
import psycopg2, psycopg2.extras, psycopg2.errorcodes
import hashlib, os, secrets, re

app = Flask(__name__)
# La secret_key è fondamentale per gestire le sessioni (login)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))

DATABASE_URL = os.environ.get("DATABASE_URL", "")

# ─────────────────────────────────────────────────────────
#  Database Helpers
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

# ─────────────────────────────────────────────────────────
#  Rotte Web (Pagine HTML)
# ─────────────────────────────────────────────────────────

@app.route("/")
def index():
    if "user_id" not in session:
        return redirect(url_for("login_page")
    return render_template("leaderboard.html")
    
# ─────────────────────────────────────────────────────────
#  API Autenticazione
# ─────────────────────────────────────────────────────────

@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.json
    u = data.get("username", "").strip()
    p = data.get("password", "")
    
    if not u or not p:
        return jsonify({"ok": False, "error": "Campi mancanti"}), 400
        
    phash = hashlib.sha256(p.encode()).hexdigest()
    
    try:
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT id, username, nome, cognome FROM users WHERE (username=%s OR email=%s) AND password_hash=%s", (u, u, phash))
                user = fetchone(cur)
                
        if user:
            # Salva i dati dell'utente nella sessione di Flask
            session.permanent = True
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            return jsonify({"ok": True})
        else:
            return jsonify({"ok": False, "error": "Credenziali errate"})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route("/api/logout", methods=["POST"])
def api_logout():
    session.clear()
    return jsonify({"ok": True})

@app.route("/api/register", methods=["POST"])
def api_register():
    data = request.json
    nome = data.get("nome", "").strip()
    cognome = data.get("cognome", "").strip()
    username = data.get("username", "").strip()
    email = data.get("email", "").strip()
    password = data.get("password", "")

    if not all([nome, cognome, username, email, password]):
        return jsonify({"ok": False, "error": "Tutti i campi sono obbligatori"}), 400
    
    if len(password) < 6:
        return jsonify({"ok": False, "error": "Password troppo corta (min 6)"}), 400

    phash = hashlib.sha256(password.encode()).hexdigest()
    api_token = secrets.token_urlsafe(24)

    try:
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO users (nome, cognome, username, email, password_hash, api_token)
                    VALUES (%s, %s, %s, %s, %s, %s)
                """, (nome, cognome, username, email, phash, api_token))
            conn.commit()
        return jsonify({"ok": True})
    except psycopg2.IntegrityError:
        return jsonify({"ok": False, "error": "Username o Email già esistenti"}), 400
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route("/api/me")
def api_me():
    if "user_id" not in session:
        return jsonify({"logged_in": False})
    
    uid = session["user_id"]
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id, nome, cognome, username, api_token FROM users WHERE id=%s", (uid,))
            u = fetchone(cur)
            if not u: return jsonify({"logged_in": False})
            
            # Recupera statistiche extra per il profilo
            cur.execute("SELECT COUNT(*) as runs, COALESCE(MAX(punteggio),0) as best, COALESCE(AVG(punteggio),0) as avg FROM sessions WHERE user_id=%s", (uid,))
            stats = fetchone(cur)
            
    return jsonify({
        "logged_in": True,
        "id": u["id"],
        "username": u["username"],
        "nome": u["nome"],
        "cognome": u["cognome"],
        "api_token": u["api_token"],
        "runs": stats["runs"],
        "best_score": round(stats["best"], 1),
        "avg_score": round(stats["avg"], 1)
    })

# ─────────────────────────────────────────────────────────
#  Logica Dati (Leaderboard, Live, etc.)
# ─────────────────────────────────────────────────────────

@app.route("/api/leaderboard")
def api_leaderboard():
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT u.username, 
                       MAX(s.punteggio) as punteggio, 
                       MAX(s.grade) as grade,
                       (SELECT ultimo_servizio FROM sessions WHERE user_id = u.id ORDER BY registrata_at DESC LIMIT 1) as ultimo_servizio,
                       COUNT(s.id) as corse,
                       EXISTS(SELECT 1 FROM live_trains WHERE user_id = u.id AND updated_at > NOW() - INTERVAL '1 minute') as online
                FROM users u
                JOIN sessions s ON u.id = s.user_id
                GROUP BY u.id, u.username
                ORDER BY punteggio DESC
            """)
            return jsonify(fetchall(cur))

@app.route("/api/live")
def api_live():
    with get_db() as conn:
        with conn.cursor() as cur:
            # Mostra i treni aggiornati negli ultimi 2 minuti
            cur.execute("""
                SELECT l.*, u.username 
                FROM live_trains l
                JOIN users u ON l.user_id = u.id
                WHERE l.updated_at > NOW() - INTERVAL '2 minutes'
                ORDER BY l.updated_at DESC
            """)
            return jsonify(fetchall(cur))

# ─────────────────────────────────────────────────────────
#  Server Start
# ─────────────────────────────────────────────────────────

if __name__ == "__main__":
    # In produzione su Render, porta e host vengono letti dalle env
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
