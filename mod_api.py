from dotenv import load_dotenv
load_dotenv()

"""
Moderation Bot API Server
Run alongside moderation.py:  python mod_api.py
Requires: pip install flask flask-cors requests pyjwt
"""

import os
import json
import time
import datetime
import requests
import jwt
from functools import wraps
from flask import Flask, request, jsonify, redirect
from flask_cors import CORS

app = Flask(__name__)
CORS(app, origins=["*"])

# ─────────────────────────────────────────────
# CONFIG — fill these in
# ─────────────────────────────────────────────
DISCORD_CLIENT_ID     = os.getenv("MOD_CLIENT_ID", "YOUR_CLIENT_ID")
DISCORD_CLIENT_SECRET = os.getenv("MOD_CLIENT_SECRET", "YOUR_CLIENT_SECRET")
DISCORD_BOT_TOKEN     = os.getenv("MOD_BOT_TOKEN", "YOUR_BOT_TOKEN")
DASHBOARD_URL         = os.getenv("DASHBOARD_URL", "http://localhost:5500/mod_dashboard.html")
REDIRECT_URI          = os.getenv("REDIRECT_URI", "http://localhost:5001/auth/callback")
JWT_SECRET            = os.getenv("JWT_SECRET", "your-secret-key-change-in-production")

DATA_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data.json")
DISCORD_API = "https://discord.com/api/v10"

# ─────────────────────────────────────────────
# DATA HELPERS
# ─────────────────────────────────────────────
def load_data():
    if not os.path.exists(DATA_FILE):
        return {"warnings": {}, "mod_logs": []}
    with open(DATA_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)
        if "mod_logs" not in data:
            data["mod_logs"] = []
        return data

def save_data(data):
    with open(DATA_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)

def log_action(guild_id, moderator, moderator_id, action, target, target_id, reason):
    data = load_data()
    data["mod_logs"].append({
        "guild_id": str(guild_id),
        "moderator": moderator,
        "moderator_id": str(moderator_id),
        "action": action,
        "target": target,
        "target_id": str(target_id),
        "reason": reason,
        "time": datetime.datetime.utcnow().isoformat()
    })
    if len(data["mod_logs"]) > 500:
        data["mod_logs"] = data["mod_logs"][-500:]
    save_data(data)

# ─────────────────────────────────────────────
# JWT HELPERS
# ─────────────────────────────────────────────
def create_token(user_id, access_token):
    payload = {
        "user_id": user_id,
        "discord_token": access_token,
        "exp": time.time() + 60 * 60 * 24 * 7
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")

def decode_token(token):
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except Exception:
        return None

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify({"error": "Unauthorized"}), 401
        payload = decode_token(auth.split(" ", 1)[1])
        if not payload:
            return jsonify({"error": "Invalid or expired token"}), 401
        request.user_payload = payload
        return f(*args, **kwargs)
    return decorated

# ─────────────────────────────────────────────
# DISCORD HELPERS
# ─────────────────────────────────────────────
def discord_get(endpoint, token):
    r = requests.get(f"{DISCORD_API}{endpoint}", headers={"Authorization": f"Bearer {token}"})
    r.raise_for_status()
    return r.json()

def bot_get(endpoint):
    r = requests.get(f"{DISCORD_API}{endpoint}", headers={"Authorization": f"Bot {DISCORD_BOT_TOKEN}"})
    r.raise_for_status()
    return r.json()

def get_bot_guild_ids():
    try:
        guilds = bot_get("/users/@me/guilds")
        return {g["id"] for g in guilds}
    except Exception:
        return set()

# ─────────────────────────────────────────────
# AUTH ROUTES
# ─────────────────────────────────────────────
@app.route("/auth/login")
def auth_login():
    params = (
        f"client_id={DISCORD_CLIENT_ID}"
        f"&redirect_uri={requests.utils.quote(REDIRECT_URI)}"
        f"&response_type=code"
        f"&scope=identify+guilds"
    )
    return redirect(f"https://discord.com/api/oauth2/authorize?{params}")

@app.route("/auth/callback")
def auth_callback():
    code = request.args.get("code")
    if not code:
        return jsonify({"error": "No code provided"}), 400
    r = requests.post(
        f"{DISCORD_API}/oauth2/token",
        data={
            "client_id": DISCORD_CLIENT_ID,
            "client_secret": DISCORD_CLIENT_SECRET,
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    if not r.ok:
        return jsonify({"error": "Failed to exchange token"}), 400
    token_data = r.json()
    access_token = token_data["access_token"]
    user = discord_get("/users/@me", access_token)
    jwt_token = create_token(user["id"], access_token)
    return redirect(f"{DASHBOARD_URL}?token={jwt_token}")

# ─────────────────────────────────────────────
# API ROUTES
# ─────────────────────────────────────────────
@app.route("/api/me")
@require_auth
def api_me():
    try:
        user = discord_get("/users/@me", request.user_payload["discord_token"])
        return jsonify(user)
    except Exception:
        return jsonify({"error": "Failed to fetch user"}), 401

@app.route("/api/guilds")
@require_auth
def api_guilds():
    try:
        user_guilds = discord_get("/users/@me/guilds", request.user_payload["discord_token"])
        bot_guild_ids = get_bot_guild_ids()
        ADMIN_PERM = 0x8
        admin_guilds = [
            g for g in user_guilds
            if (int(g["permissions"]) & ADMIN_PERM) and g["id"] in bot_guild_ids
        ]
        return jsonify(admin_guilds)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/guild/<guild_id>/members")
@require_auth
def api_members(guild_id):
    try:
        members = bot_get(f"/guilds/{guild_id}/members?limit=100")
        result = []
        for m in members:
            user = m.get("user", {})
            if user.get("bot"):
                continue
            result.append({
                "id": user.get("id"),
                "username": user.get("username"),
                "discriminator": user.get("discriminator", "0"),
                "avatar": user.get("avatar"),
                "nick": m.get("nick"),
                "roles": m.get("roles", []),
                "joined_at": m.get("joined_at"),
                "timed_out_until": m.get("communication_disabled_until"),
            })
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/guild/<guild_id>/warnings/<user_id>", methods=["GET"])
@require_auth
def api_get_warnings(guild_id, user_id):
    data = load_data()
    warns = data.get("warnings", {}).get(guild_id, {}).get(user_id, [])
    return jsonify(warns)

@app.route("/api/guild/<guild_id>/warnings/<user_id>", methods=["DELETE"])
@require_auth
def api_clear_warnings(guild_id, user_id):
    data = load_data()
    moderator_id = request.user_payload.get("user_id", "Dashboard")
    if guild_id in data.get("warnings", {}) and user_id in data["warnings"][guild_id]:
        data["warnings"][guild_id][user_id] = []
        save_data(data)
        log_action(guild_id, "Dashboard", moderator_id, "clearwarnings", f"User {user_id}", user_id, "Cleared via dashboard")
    return jsonify({"ok": True})

@app.route("/api/guild/<guild_id>/logs")
@require_auth
def api_logs(guild_id):
    data = load_data()
    logs = [l for l in data.get("mod_logs", []) if l.get("guild_id") == guild_id]
    logs.reverse()
    return jsonify(logs)

@app.route("/api/guild/<guild_id>/stats")
@require_auth
def api_stats(guild_id):
    data = load_data()
    logs = [l for l in data.get("mod_logs", []) if l.get("guild_id") == guild_id]
    warnings_data = data.get("warnings", {}).get(guild_id, {})
    total_warns = sum(len(v) for v in warnings_data.values())
    action_counts = {}
    for l in logs:
        a = l["action"]
        action_counts[a] = action_counts.get(a, 0) + 1
    return jsonify({
        "total_actions": len(logs),
        "total_warnings": total_warns,
        "action_counts": action_counts,
        "warned_users": len([u for u, w in warnings_data.items() if len(w) > 0])
    })

@app.route("/api/guild/<guild_id>/action", methods=["POST"])
@require_auth
def api_action(guild_id):
    body = request.json
    action = body.get("action")
    user_id = body.get("user_id")
    reason = body.get("reason", "Action via dashboard")
    minutes = body.get("minutes", 60)
    moderator_id = request.user_payload.get("user_id", "Dashboard")

    headers = {"Authorization": f"Bot {DISCORD_BOT_TOKEN}", "Content-Type": "application/json"}

    try:
        if action == "kick":
            requests.delete(f"{DISCORD_API}/guilds/{guild_id}/members/{user_id}", headers=headers)
            log_action(guild_id, "Dashboard", moderator_id, "kick", f"User {user_id}", user_id, reason)

        elif action == "ban":
            requests.put(f"{DISCORD_API}/guilds/{guild_id}/bans/{user_id}", json={"delete_message_seconds": 0}, headers=headers)
            log_action(guild_id, "Dashboard", moderator_id, "ban", f"User {user_id}", user_id, reason)

        elif action == "unban":
            requests.delete(f"{DISCORD_API}/guilds/{guild_id}/bans/{user_id}", headers=headers)
            log_action(guild_id, "Dashboard", moderator_id, "unban", f"User {user_id}", user_id, reason)

        elif action == "timeout":
            until = (datetime.datetime.utcnow() + datetime.timedelta(minutes=int(minutes))).strftime("%Y-%m-%dT%H:%M:%S.000Z")
            requests.patch(f"{DISCORD_API}/guilds/{guild_id}/members/{user_id}", json={"communication_disabled_until": until}, headers=headers)
            log_action(guild_id, "Dashboard", moderator_id, "timeout", f"User {user_id}", user_id, f"{minutes}min | {reason}")

        elif action == "untimeout":
            requests.patch(f"{DISCORD_API}/guilds/{guild_id}/members/{user_id}", json={"communication_disabled_until": None}, headers=headers)
            log_action(guild_id, "Dashboard", moderator_id, "untimeout", f"User {user_id}", user_id, reason)

        elif action == "warn":
            data = load_data()
            data.setdefault("warnings", {}).setdefault(guild_id, {}).setdefault(user_id, [])
            data["warnings"][guild_id][user_id].append({
                "reason": reason,
                "time": datetime.datetime.utcnow().isoformat()
            })
            save_data(data)
            log_action(guild_id, "Dashboard", moderator_id, "warn", f"User {user_id}", user_id, reason)

        else:
            return jsonify({"error": "Unknown action"}), 400

        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/health")
def health():
    return jsonify({"status": "ok"})

if __name__ == "__main__":
    print("=" * 50)
    print("Moderation API starting on http://localhost:5001")
    print("=" * 50)
    print(f"  Client ID set:     {'YES' if DISCORD_CLIENT_ID != 'YOUR_CLIENT_ID' else 'NO — edit mod_api.py'}")
    print(f"  Client secret set: {'YES' if DISCORD_CLIENT_SECRET != 'YOUR_CLIENT_SECRET' else 'NO — edit mod_api.py'}")
    print(f"  Bot token set:     {'YES' if DISCORD_BOT_TOKEN != 'YOUR_BOT_TOKEN' else 'NO — edit mod_api.py'}")
    print(f"  Redirect URI:      {REDIRECT_URI}")
    print(f"  Dashboard URL:     {DASHBOARD_URL}")
    print("=" * 50)
    app.run(debug=True, port=5001)
