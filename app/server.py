"""
app/server.py — Serveur Flask local pour l'extension navigateur
================================================================
Écoute sur http://127.0.0.1:7890
Authentification : session token unique généré au démarrage

L'extension navigateur communique avec ce serveur via HTTP.
Toutes les routes sont protégées par le header X-PyVault-Token.
"""

import os
import sys
import json
import secrets
import webbrowser
import threading
from functools import wraps
from pathlib import Path
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS

# Ajouter le répertoire parent au path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.vault import VaultDB, VaultEntry
from core.generator import generate_password, estimate_entropy, PasswordPolicy, check_password_breach
from core.github_sync import GitHubSync

# ── Configuration ─────────────────────────────────────────────────────────────
PORT            = 7890
HOST            = "127.0.0.1"   # Jamais 0.0.0.0 — accès local uniquement
DB_PATH         = "~/.pyvault/vault.db"
CONFIG_PATH     = "~/.pyvault/config.json"
SESSION_TOKEN   = secrets.token_hex(32)   # Régénéré à chaque démarrage

app   = Flask(__name__, template_folder="templates", static_folder="static")
vault = VaultDB(DB_PATH)

# CORS : uniquement les extensions Chrome/Firefox et localhost
CORS(app, resources={
    r"/api/*": {
        "origins": [
            "chrome-extension://*",
            "moz-extension://*",
            f"http://{HOST}:{PORT}",
        ]
    }
})

# ── Décorateur d'authentification ─────────────────────────────────────────────

def require_token(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("X-PyVault-Token") or request.args.get("token")
        if token != SESSION_TOKEN:
            return jsonify({"error": "Token invalide"}), 401
        return f(*args, **kwargs)
    return decorated


def require_unlocked(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not vault.is_unlocked:
            return jsonify({"error": "Vault verrouillé"}), 403
        return f(*args, **kwargs)
    return decorated


# ── Routes d'authentification ─────────────────────────────────────────────────

@app.route("/api/vault/status")
@require_token
def vault_status():
    """Statut du vault : existence, déverrouillage."""
    db_path = Path(DB_PATH).expanduser()
    return jsonify({
        "exists":     db_path.exists(),
        "unlocked":   vault.is_unlocked,
        "version":    "1.0.0",
    })


@app.route("/api/vault/init", methods=["POST"])
@require_token
def vault_init():
    """Crée un nouveau vault."""
    data = request.json or {}
    master_pwd = data.get("master_password", "")
    if len(master_pwd) < 12:
        return jsonify({"error": "Le mot de passe maître doit contenir au moins 12 caractères."}), 400
    try:
        vault.init_new(master_pwd)
        return jsonify({"success": True, "message": "Vault créé avec succès."})
    except FileExistsError:
        return jsonify({"error": "Un vault existe déjà."}), 409
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/vault/unlock", methods=["POST"])
@require_token
def vault_unlock():
    """Déverrouille le vault avec le mot de passe maître."""
    data = request.json or {}
    master_pwd = data.get("master_password", "")
    try:
        success = vault.unlock(master_pwd)
        if success:
            return jsonify({"success": True, "message": "Vault déverrouillé."})
        else:
            return jsonify({"error": "Mot de passe maître incorrect."}), 401
    except FileNotFoundError:
        return jsonify({"error": "Aucun vault trouvé. Créez-en un d'abord."}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/vault/lock", methods=["POST"])
@require_token
def vault_lock():
    vault.lock()
    return jsonify({"success": True, "message": "Vault verrouillé."})


@app.route("/api/vault/change-password", methods=["POST"])
@require_token
@require_unlocked
def change_master_password():
    data = request.json or {}
    old_pwd = data.get("old_password", "")
    new_pwd = data.get("new_password", "")
    if len(new_pwd) < 12:
        return jsonify({"error": "Nouveau mot de passe trop court (min 12 caractères)."}), 400
    try:
        success = vault.change_master_password(old_pwd, new_pwd)
        if success:
            return jsonify({"success": True})
        else:
            return jsonify({"error": "Ancien mot de passe incorrect."}), 401
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── Routes CRUD des entrées ───────────────────────────────────────────────────

@app.route("/api/entries", methods=["GET"])
@require_token
@require_unlocked
def get_entries():
    query = request.args.get("q", "")
    entries = vault.search_entries(query) if query else vault.get_all_entries()
    return jsonify([_entry_to_dict(e, include_password=False) for e in entries])


@app.route("/api/entries/by-url", methods=["GET"])
@require_token
@require_unlocked
def get_entries_by_url():
    """Utilisé par l'extension pour l'auto-fill."""
    url = request.args.get("url", "")
    entries = vault.get_by_url(url)
    return jsonify([_entry_to_dict(e, include_password=False) for e in entries])


@app.route("/api/entries/<int:entry_id>", methods=["GET"])
@require_token
@require_unlocked
def get_entry(entry_id):
    entry = vault.get_entry(entry_id)
    if entry is None:
        return jsonify({"error": "Entrée introuvable."}), 404
    return jsonify(_entry_to_dict(entry, include_password=True))


@app.route("/api/entries", methods=["POST"])
@require_token
@require_unlocked
def add_entry():
    data = request.json or {}
    if not data.get("site_name") or not data.get("password"):
        return jsonify({"error": "site_name et password sont obligatoires."}), 400
    entry = VaultEntry(
        id=None,
        site_name=data["site_name"],
        site_url=data.get("site_url", ""),
        username=data.get("username", ""),
        password=data["password"],
        notes=data.get("notes", ""),
        category=data.get("category", "Général"),
        created_at="",
        updated_at="",
        is_favorite=data.get("is_favorite", False),
    )
    entry_id = vault.add_entry(entry)
    return jsonify({"success": True, "id": entry_id}), 201


@app.route("/api/entries/<int:entry_id>", methods=["PUT"])
@require_token
@require_unlocked
def update_entry(entry_id):
    data = request.json or {}
    existing = vault.get_entry(entry_id)
    if not existing:
        return jsonify({"error": "Entrée introuvable."}), 404
    existing.site_name   = data.get("site_name",  existing.site_name)
    existing.site_url    = data.get("site_url",   existing.site_url)
    existing.username    = data.get("username",   existing.username)
    existing.password    = data.get("password",   existing.password)
    existing.notes       = data.get("notes",      existing.notes)
    existing.category    = data.get("category",   existing.category)
    existing.is_favorite = data.get("is_favorite",existing.is_favorite)
    vault.update_entry(existing)
    return jsonify({"success": True})


@app.route("/api/entries/<int:entry_id>", methods=["DELETE"])
@require_token
@require_unlocked
def delete_entry(entry_id):
    vault.delete_entry(entry_id)
    return jsonify({"success": True})


# ── Générateur de mots de passe ───────────────────────────────────────────────

@app.route("/api/generate", methods=["POST"])
@require_token
def generate():
    data = request.json or {}
    policy = PasswordPolicy(
        length=int(data.get("length", 20)),
        use_uppercase=data.get("uppercase", True),
        use_lowercase=data.get("lowercase", True),
        use_digits=data.get("digits", True),
        use_symbols=data.get("symbols", True),
        exclude_ambiguous=data.get("exclude_ambiguous", True),
        min_uppercase=int(data.get("min_uppercase", 1)),
        min_lowercase=int(data.get("min_lowercase", 1)),
        min_digits=int(data.get("min_digits", 1)),
        min_symbols=int(data.get("min_symbols", 1)),
    )
    password = generate_password(policy)
    entropy  = estimate_entropy(password)
    return jsonify({"password": password, "entropy": entropy})


@app.route("/api/check-breach", methods=["POST"])
@require_token
def check_breach():
    data = request.json or {}
    password = data.get("password", "")
    if not password:
        return jsonify({"error": "Mot de passe manquant."}), 400
    result = check_password_breach(password)
    return jsonify(result)


@app.route("/api/analyze-password", methods=["POST"])
@require_token
def analyze_password():
    data = request.json or {}
    password = data.get("password", "")
    return jsonify(estimate_entropy(password))


# ── Statistiques ──────────────────────────────────────────────────────────────

@app.route("/api/stats")
@require_token
@require_unlocked
def get_stats():
    return jsonify(vault.get_stats())


# ── Synchronisation GitHub ────────────────────────────────────────────────────

@app.route("/api/sync/status")
@require_token
def sync_status():
    config = _load_config()
    if not config.get("github_token"):
        return jsonify({"configured": False})
    sync = GitHubSync(config)
    status = sync.get_sync_status()
    status["configured"] = True
    return jsonify(status)


@app.route("/api/sync/push", methods=["POST"])
@require_token
@require_unlocked
def sync_push():
    config = _load_config()
    if not config.get("github_token"):
        return jsonify({"error": "GitHub non configuré."}), 400
    try:
        sync = GitHubSync(config)
        sync.ensure_repo_exists()
        result = sync.push(DB_PATH)
        return jsonify({"success": True, "commit": result.get("commit", {}).get("sha", "")})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/sync/pull", methods=["POST"])
@require_token
def sync_pull():
    config = _load_config()
    if not config.get("github_token"):
        return jsonify({"error": "GitHub non configuré."}), 400
    try:
        vault.lock()
        sync = GitHubSync(config)
        result = sync.pull(DB_PATH)
        return jsonify({"success": True, "sha256": result["sha256"]})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/config", methods=["GET", "POST"])
@require_token
def config_route():
    if request.method == "GET":
        config = _load_config()
        # Ne pas exposer les tokens en entier
        safe = {k: v for k, v in config.items()}
        if "github_token" in safe and safe["github_token"]:
            safe["github_token"] = safe["github_token"][:8] + "****"
        return jsonify(safe)
    else:
        data = request.json or {}
        config = _load_config()
        config.update(data)
        _save_config(config)
        return jsonify({"success": True})


# ── Interface Web (SPA) ───────────────────────────────────────────────────────

@app.route("/")
def index():
    return send_from_directory("templates", "index.html")


@app.route("/token")
def get_token():
    """Endpoint local uniquement — retourne le token de session pour la configuration."""
    return jsonify({"session_token": SESSION_TOKEN, "port": PORT})


# ── Utilitaires ───────────────────────────────────────────────────────────────

def _entry_to_dict(entry: VaultEntry, include_password: bool) -> dict:
    d = {
        "id":          entry.id,
        "site_name":   entry.site_name,
        "site_url":    entry.site_url,
        "username":    entry.username,
        "notes":       entry.notes,
        "category":    entry.category,
        "created_at":  entry.created_at,
        "updated_at":  entry.updated_at,
        "is_favorite": entry.is_favorite,
    }
    if include_password:
        d["password"] = entry.password
    return d


def _load_config() -> dict:
    config_file = Path(CONFIG_PATH).expanduser()
    if config_file.exists():
        return json.loads(config_file.read_text())
    return {}


def _save_config(config: dict) -> None:
    config_file = Path(CONFIG_PATH).expanduser()
    config_file.parent.mkdir(parents=True, exist_ok=True)
    config_file.write_text(json.dumps(config, indent=2, ensure_ascii=False))
    config_file.chmod(0o600)


def start_server(open_browser: bool = True) -> None:
    """Démarre le serveur Flask et ouvre le navigateur."""
    print(f"\n{'─'*55}")
    print(f"  PyVault — Gestionnaire de mots de passe sécurisé")
    print(f"  Interface : http://{HOST}:{PORT}")
    print(f"  Token de session : {SESSION_TOKEN[:16]}...")
    print(f"{'─'*55}\n")
    print("  Enregistrez ce token dans l'extension navigateur.")
    print("  Il change à chaque démarrage du serveur.\n")

    # Sauvegarder le token pour l'extension (accessible uniquement localement)
    token_file = Path("~/.pyvault/.session_token").expanduser()
    token_file.write_text(SESSION_TOKEN)
    token_file.chmod(0o600)

    if open_browser:
        threading.Timer(1.0, lambda: webbrowser.open(f"http://{HOST}:{PORT}")).start()

    app.run(host=HOST, port=PORT, debug=False, use_reloader=False)
