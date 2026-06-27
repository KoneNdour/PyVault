"""
core/github_sync.py — Sauvegarde chiffrée du vault sur GitHub
==============================================================
IMPORTANT : Seul le fichier vault.db CHIFFRÉ est poussé sur GitHub.
Le mot de passe maître ne quitte JAMAIS la machine locale.
Le vault chiffré sur GitHub est inutilisable sans le mot de passe maître.

Configuration requise dans config.json :
  {
    "github_token":  "ghp_votre_token_ici",
    "github_user":   "votre_username",
    "github_repo":   "mon-vault-prive",
    "github_branch": "main"
  }

Créer le token sur : https://github.com/settings/tokens
Permissions requises : repo (accès complet aux repositories privés)
"""

import base64
import json
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
import requests


class GitHubSync:
    """Synchronisation du vault chiffré vers un dépôt GitHub privé."""

    VAULT_REMOTE_PATH = "vault.db"    # Chemin dans le repo GitHub
    META_REMOTE_PATH  = "sync_meta.json"
    API_BASE          = "https://api.github.com"

    def __init__(self, config: dict):
        self.token  = config["github_token"]
        self.user   = config["github_user"]
        self.repo   = config["github_repo"]
        self.branch = config.get("github_branch", "main")
        self._headers = {
            "Authorization": f"token {self.token}",
            "Accept":        "application/vnd.github.v3+json",
            "User-Agent":    "PyVault/1.0",
        }

    # ── Opérations principales ───────────────────────────────────────────────

    def push(self, vault_path: str) -> dict:
        """
        Pousse le vault chiffré sur GitHub.
        Retourne les informations du commit créé.
        """
        vault_file = Path(vault_path).expanduser()
        if not vault_file.exists():
            raise FileNotFoundError(f"Vault introuvable : {vault_file}")

        raw = vault_file.read_bytes()
        content_b64 = base64.b64encode(raw).decode()
        sha256 = hashlib.sha256(raw).hexdigest()

        # Récupérer le SHA du fichier existant (pour la mise à jour)
        existing_sha = self._get_file_sha(self.VAULT_REMOTE_PATH)

        # Message de commit avec horodatage UTC
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        message = f"vault: sync {now} | sha256:{sha256[:12]}"

        body = {
            "message": message,
            "content": content_b64,
            "branch":  self.branch,
        }
        if existing_sha:
            body["sha"] = existing_sha  # Obligatoire pour mettre à jour un fichier existant

        url = f"{self.API_BASE}/repos/{self.user}/{self.repo}/contents/{self.VAULT_REMOTE_PATH}"
        resp = requests.put(url, headers=self._headers, json=body, timeout=30)
        resp.raise_for_status()

        # Mettre à jour les métadonnées de synchronisation
        self._push_meta({
            "last_push": now,
            "sha256":    sha256,
            "vault_size_bytes": len(raw),
        })

        return resp.json()

    def pull(self, vault_path: str) -> dict:
        """
        Télécharge le vault chiffré depuis GitHub et l'écrit localement.
        ATTENTION : écrase le vault local existant.
        """
        url = f"{self.API_BASE}/repos/{self.user}/{self.repo}/contents/{self.VAULT_REMOTE_PATH}"
        params = {"ref": self.branch}
        resp = requests.get(url, headers=self._headers, params=params, timeout=30)
        resp.raise_for_status()

        data = resp.json()
        content = base64.b64decode(data["content"])

        vault_file = Path(vault_path).expanduser()
        vault_file.parent.mkdir(parents=True, exist_ok=True)
        vault_file.write_bytes(content)

        sha256 = hashlib.sha256(content).hexdigest()
        return {
            "sha256":            sha256,
            "size":              len(content),
            "github_commit_sha": data.get("sha", ""),
        }

    def get_sync_status(self) -> dict:
        """Retourne les informations de synchronisation depuis GitHub."""
        try:
            meta = self._get_remote_meta()
            vault_info = self._get_file_info(self.VAULT_REMOTE_PATH)
            return {
                "connected":  True,
                "last_push":  meta.get("last_push", "jamais"),
                "sha256":     meta.get("sha256", ""),
                "vault_size": meta.get("vault_size_bytes", 0),
                "repo":       f"{self.user}/{self.repo}",
                "branch":     self.branch,
            }
        except Exception as e:
            return {"connected": False, "error": str(e)}

    def ensure_repo_exists(self) -> bool:
        """
        Vérifie que le dépôt GitHub existe.
        Propose de le créer si absent (privé par défaut).
        """
        url = f"{self.API_BASE}/repos/{self.user}/{self.repo}"
        resp = requests.get(url, headers=self._headers, timeout=10)

        if resp.status_code == 200:
            info = resp.json()
            if info.get("private"):
                return True
            else:
                print(f"⚠  Le repo {self.repo} est PUBLIC. Rendez-le PRIVÉ sur GitHub.")
                return True
        elif resp.status_code == 404:
            return self._create_repo()
        else:
            resp.raise_for_status()

    def _create_repo(self) -> bool:
        """Crée un dépôt privé sur GitHub."""
        url = f"{self.API_BASE}/user/repos"
        body = {
            "name":        self.repo,
            "description": "PyVault — Vault de mots de passe chiffré (AES-256-GCM)",
            "private":     True,
            "auto_init":   True,
        }
        resp = requests.post(url, headers=self._headers, json=body, timeout=15)
        resp.raise_for_status()
        print(f"✔  Dépôt privé créé : {self.user}/{self.repo}")
        return True

    # ── Utilitaires ─────────────────────────────────────────────────────────

    def _get_file_sha(self, path: str) -> Optional[str]:
        """Récupère le SHA GitHub d'un fichier (nécessaire pour les mises à jour)."""
        info = self._get_file_info(path)
        return info.get("sha") if info else None

    def _get_file_info(self, path: str) -> Optional[dict]:
        url = f"{self.API_BASE}/repos/{self.user}/{self.repo}/contents/{path}"
        resp = requests.get(url, headers=self._headers,
                            params={"ref": self.branch}, timeout=10)
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        return resp.json()

    def _push_meta(self, meta: dict) -> None:
        """Pousse les métadonnées de synchronisation (fichier non sensible)."""
        content = json.dumps(meta, indent=2, ensure_ascii=False)
        content_b64 = base64.b64encode(content.encode()).decode()
        existing_sha = self._get_file_sha(self.META_REMOTE_PATH)

        body = {
            "message": f"meta: update sync info {meta['last_push']}",
            "content": content_b64,
            "branch":  self.branch,
        }
        if existing_sha:
            body["sha"] = existing_sha

        url = f"{self.API_BASE}/repos/{self.user}/{self.repo}/contents/{self.META_REMOTE_PATH}"
        requests.put(url, headers=self._headers, json=body, timeout=15)

    def _get_remote_meta(self) -> dict:
        info = self._get_file_info(self.META_REMOTE_PATH)
        if not info:
            return {}
        content = base64.b64decode(info["content"])
        return json.loads(content)
