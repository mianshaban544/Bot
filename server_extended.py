from flask import Flask, request, redirect, jsonify
from flask_socketio import SocketIO, join_room, emit
from urllib.parse import urlencode
import requests, jwt, time, sqlite3, os, json, bcrypt

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET", "devsecret")
socketio = SocketIO(app, cors_allowed_origins="*")

DISCORD_CLIENT_ID = os.getenv("DISCORD_CLIENT_ID", "1429557311634149547")
DISCORD_CLIENT_SECRET = os.getenv("DISCORD_CLIENT_SECRET", "h1dOS28JTkuBz-t1l-RZY91zfXZFE5J7")
BASE_URL = os.getenv("BASE_URL", "http://localhost:5000")
JWT_SECRET = os.getenv("JWT_SECRET", "h4mb0ATqhStjfRa4B7GUbaV0aLvFpvnV")
DB = os.getenv("DB_PATH", "users.db")
ADMIN_KEY = os.getenv("ADMIN_KEY", "adminkey")
FLASK_SECRET = your_secret
BASE_URL = https://<render-app-name>.onrender.com

# ================= DB Helpers =================
def init_db():
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users(
        discord_id TEXT UNIQUE,
        username   TEXT UNIQUE,
        password_hash TEXT,
        permissions   TEXT,
        valid_until   INTEGER,
        PRIMARY KEY(username)
    )
    """)
    conn.commit(); conn.close()

def upsert_user_record(discord_id, username, permissions, password_hash=None, valid_until=None):
    conn = sqlite3.connect(DB); cur = conn.cursor()
    cur.execute("SELECT username FROM users WHERE username=?", (username,))
    row = cur.fetchone()
    if row:
        cur.execute("UPDATE users SET discord_id=?, permissions=?, password_hash=COALESCE(?, password_hash), valid_until=? WHERE username=?",
                    (discord_id, json.dumps(permissions or {}), password_hash, valid_until, username))
    else:
        cur.execute("INSERT INTO users(discord_id, username, password_hash, permissions, valid_until) VALUES(?,?,?,?,?)",
                    (discord_id, username, password_hash, json.dumps(permissions or {}), valid_until))
    conn.commit(); conn.close()

def get_user_by_username(username):
    conn = sqlite3.connect(DB); cur = conn.cursor()
    cur.execute("SELECT discord_id, username, password_hash, permissions, valid_until FROM users WHERE username=?", (username,))
    row = cur.fetchone(); conn.close()
    if not row: return None
    perms = json.loads(row[3]) if row[3] else {}
    return {"discord_id": row[0], "username": row[1], "password_hash": row[2], "permissions": perms, "valid_until": row[4]}

def get_user_by_discord(discord_id):
    conn = sqlite3.connect(DB); cur = conn.cursor()
    cur.execute("SELECT discord_id, username, password_hash, permissions, valid_until FROM users WHERE discord_id=?", (discord_id,))
    row = cur.fetchone(); conn.close()
    if not row: return None
    perms = json.loads(row[3]) if row[3] else {}
    return {"discord_id": row[0], "username": row[1], "password_hash": row[2], "permissions": perms, "valid_until": row[4]}

def ensure_not_expired(user):
    now = int(time.time())
    vu = user.get("valid_until")
    if vu and now > vu:
        return False
    perms = user.get("permissions", {})
    expmap = perms.get("_expiry", {})
    changed = False
    if isinstance(expmap, dict):
        for k, ts in list(expmap.items()):
            if isinstance(ts, int) and now > ts:
                perms[k] = False
                del expmap[k]
                changed = True
        if changed:
            upsert_user_record(user.get("discord_id"), user.get("username"), perms, None, user.get("valid_until"))
    return True

# ================= Routes =================
@app.route("/")
def home():
    return "Server Online ✅"

# ---- Discord OAuth ----
@app.route("/auth/discord/login")
def login_discord():
    params = {
        "client_id": DISCORD_CLIENT_ID,
        "redirect_uri": f"{BASE_URL}/auth/discord/callback",
        "response_type": "code",
        "scope": "identify"
    }
    return redirect("https://discord.com/api/oauth2/authorize?" + urlencode(params))

@app.route("/auth/discord/callback")
def callback():
    code = request.args.get("code")
    if not code: return "No code provided", 400
    data = {
        "client_id": DISCORD_CLIENT_ID,
        "client_secret": DISCORD_CLIENT_SECRET,
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": f"{BASE_URL}/auth/discord/callback"
    }
    r = requests.post("https://discord.com/api/oauth2/token", data=data, timeout=10)
    token = r.json().get("access_token")
    user = requests.get("https://discord.com/api/users/@me", headers={"Authorization": f"Bearer {token}"}).json()
    discord_id, username = user.get("id"), user.get("username")
    perms = {"can_run_mine": True, "can_run_demorgan": True, "can_run_fuelm": False, "can_run_gym": False, "is_admin": False, "all_access": False}
    upsert_user_record(discord_id, username, perms)
    jwt_token = jwt.encode({"sub": username, "exp": int(time.time())+86400}, JWT_SECRET, algorithm="HS256")
    return f"✅ Login OK! Token:\n\n{jwt_token}"

# ---- Username/Password Login ----
@app.route("/auth/login", methods=["POST"])
def login_user():
    body = request.json or {}
    u, p = body.get("username"), body.get("password")
    user = get_user_by_username(u)
    if not user or not user["password_hash"]: return jsonify({"error": "invalid"}), 401
    if not bcrypt.checkpw(p.encode(), user["password_hash"].encode()): return jsonify({"error": "invalid"}), 401
    if not ensure_not_expired(user): return jsonify({"error": "expired"}), 403
    token = jwt.encode({"sub": u, "exp": int(time.time())+86400}, JWT_SECRET, algorithm="HS256")
    return jsonify({"token": token, "permissions": user["permissions"], "valid_until": user["valid_until"]})

# ---- Admin Endpoints ----
@app.route("/admin/create-user", methods=["POST"])
def admin_create_user():
    if request.headers.get("X-ADMIN-KEY") != ADMIN_KEY: return jsonify({"error": "unauthorized"}), 401
    body = request.json or {}
    u, p, d = body.get("username"), body.get("password"), body.get("duration_minutes", 0)
    phash = bcrypt.hashpw(p.encode(), bcrypt.gensalt()).decode()
    valid_until = int(time.time()) + int(d*60) if d else None
    upsert_user_record(None, u, body.get("permissions", {}), phash, valid_until)
    return jsonify({"ok": True, "valid_until": valid_until})

@app.route("/admin/set-permissions", methods=["POST"])
def set_perms():
    if request.headers.get("X-ADMIN-KEY") != ADMIN_KEY: return jsonify({"error": "unauthorized"}), 401
    body = request.json
    u = get_user_by_username(body.get("username"))
    upsert_user_record(u["discord_id"], u["username"], body["permissions"], None, u["valid_until"])
    socketio.emit("permissions", {"permissions": body["permissions"]}, room=u["username"])
    return jsonify({"ok": True})

# --- Get user info by username (ADMIN) ---
@app.route("/admin/get-user")
def admin_get_user():
    key = request.headers.get("X-ADMIN-KEY", "")
    if key != ADMIN_KEY:
        return jsonify({"error": "unauthorized"}), 401

    username = request.args.get("username")
    if not username:
        return jsonify({"error": "username required"}), 400

    user = get_user_by_username(username)
    if not user:
        return jsonify({"error": "user not found"}), 404

    return jsonify(user)

# --- Delete user by username (ADMIN) ---
@app.route("/admin/delete-user", methods=["POST"])
def admin_delete_user():
    key = request.headers.get("X-ADMIN-KEY", "")
    if key != ADMIN_KEY:
        return jsonify({"error": "unauthorized"}), 401

    body = request.json or {}
    username = body.get("username")
    if not username:
        return jsonify({"error": "username required"}), 400

    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    cur.execute("DELETE FROM users WHERE username=?", (username,))
    conn.commit()
    conn.close()

    return jsonify({"ok": True, "deleted": username})


@app.route("/logs", methods=["POST"])
def logs():
    print("📜", request.json); return jsonify({"ok": True})

# ---- Socket.IO ----
@socketio.on("connect")
def on_connect(auth):
    token = auth.get("token") if isinstance(auth, dict) else None
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        user = get_user_by_username(payload["sub"])
        join_room(payload["sub"])
        emit("permissions", {"permissions": user["permissions"]})
        print("✅ Socket connected for", payload["sub"])
    except Exception as e:
        print("❌", e); return False

if __name__ == "__main__":
    init_db()
    socketio.run(app, host="0.0.0.0", port=5000)
