"""
core/vault.py — Base de données chiffrée du gestionnaire de mots de passe
==========================================================================
Architecture :
  - Base SQLite locale (vault.db)
  - Chaque champ sensible est chiffré individuellement avec AES-256-GCM
  - La clé de chiffrement est dérivée du mot de passe maître via Argon2id
  - Le fichier vault.db peut être sauvegardé/partagé sans risque
    (inutilisable sans le mot de passe maître)
"""

import sqlite3
import secrets
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, List
from dataclasses import dataclass

from .crypto import VaultCrypto, generate_salt, create_verification_blob, verify_master_password

VAULT_VERSION = "1.0.0"


@dataclass
class VaultEntry:
    id:           Optional[int]
    site_name:    str
    site_url:     str
    username:     str
    password:     str
    notes:        str
    category:     str
    created_at:   str
    updated_at:   str
    is_favorite:  bool = False


class VaultDB:
    """
    Gestionnaire du vault SQLite chiffré.

    Usage :
        vault = VaultDB("~/.pyvault/vault.db")
        vault.init_new("MonMotDePasseMaitre!")
        # ou
        vault.unlock("MonMotDePasseMaitre!")

        vault.add_entry(VaultEntry(...))
        entries = vault.search_entries("github")
        vault.close()
    """

    def __init__(self, db_path: str = "~/.pyvault/vault.db"):
        self.db_path = Path(db_path).expanduser()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn: Optional[sqlite3.Connection] = None
        self._crypto: Optional[VaultCrypto] = None
        self.is_unlocked = False
        self._session_token = secrets.token_hex(32)

    # ── Initialisation ───────────────────────────────────────────────────────

    def init_new(self, master_password: str) -> None:
        """Crée un nouveau vault vide protégé par le mot de passe maître."""
        if self.db_path.exists():
            raise FileExistsError(f"Un vault existe déjà : {self.db_path}")

        self._conn = sqlite3.connect(self.db_path)
        self._conn.row_factory = sqlite3.Row

        # Générer le sel et créer la clé
        salt = generate_salt()
        self._crypto = VaultCrypto(master_password, salt)
        verification_blob = create_verification_blob(master_password, salt)

        self._create_schema()

        # Stocker les métadonnées du vault
        self._conn.execute(
            "INSERT INTO vault_meta VALUES (?,?,?,?,?,?)",
            (
                VAULT_VERSION,
                VaultCrypto.to_b64(salt),
                VaultCrypto.to_b64(verification_blob),
                datetime.now(timezone.utc).isoformat(),
                datetime.now(timezone.utc).isoformat(),
                0,
            ),
        )
        self._conn.commit()
        self.is_unlocked = True

    def unlock(self, master_password: str) -> bool:
        """
        Déverrouille un vault existant.
        Retourne True si le mot de passe est correct, False sinon.
        """
        if not self.db_path.exists():
            raise FileNotFoundError(f"Vault introuvable : {self.db_path}")

        self._conn = sqlite3.connect(self.db_path)
        self._conn.row_factory = sqlite3.Row

        row = self._conn.execute(
            "SELECT salt_b64, verification_b64 FROM vault_meta"
        ).fetchone()

        salt               = VaultCrypto.from_b64(row["salt_b64"])
        verification_blob  = VaultCrypto.from_b64(row["verification_b64"])

        if not verify_master_password(master_password, salt, verification_blob):
            self._conn.close()
            self._conn = None
            return False

        self._crypto = VaultCrypto(master_password, salt)
        self.is_unlocked = True

        # Mettre à jour la date de dernier accès
        self._conn.execute(
            "UPDATE vault_meta SET last_accessed_at=?",
            (datetime.now(timezone.utc).isoformat(),)
        )
        self._conn.commit()
        return True

    def lock(self) -> None:
        """Verrouille le vault en supprimant la clé de la mémoire."""
        self._crypto = None
        self.is_unlocked = False

    def close(self) -> None:
        self.lock()
        if self._conn:
            self._conn.close()
            self._conn = None

    # ── CRUD ─────────────────────────────────────────────────────────────────

    def add_entry(self, entry: VaultEntry) -> int:
        """Ajoute un enregistrement chiffré. Retourne l'ID inséré."""
        self._require_unlocked()
        now = datetime.now(timezone.utc).isoformat()
        cursor = self._conn.execute(
            """INSERT INTO entries
               (site_name, site_url_enc, username_enc, password_enc,
                notes_enc, category, created_at, updated_at, is_favorite)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (
                entry.site_name,
                self._enc(entry.site_url),
                self._enc(entry.username),
                self._enc(entry.password),
                self._enc(entry.notes or ""),
                entry.category or "Général",
                now, now,
                int(entry.is_favorite),
            ),
        )
        self._conn.commit()
        self._update_count()
        return cursor.lastrowid

    def update_entry(self, entry: VaultEntry) -> None:
        """Met à jour un enregistrement existant."""
        self._require_unlocked()
        self._conn.execute(
            """UPDATE entries SET
               site_name=?, site_url_enc=?, username_enc=?,
               password_enc=?, notes_enc=?, category=?,
               updated_at=?, is_favorite=?
               WHERE id=?""",
            (
                entry.site_name,
                self._enc(entry.site_url),
                self._enc(entry.username),
                self._enc(entry.password),
                self._enc(entry.notes or ""),
                entry.category,
                datetime.now(timezone.utc).isoformat(),
                int(entry.is_favorite),
                entry.id,
            ),
        )
        self._conn.commit()

    def delete_entry(self, entry_id: int) -> None:
        self._require_unlocked()
        self._conn.execute("DELETE FROM entries WHERE id=?", (entry_id,))
        self._conn.commit()
        self._update_count()

    def get_entry(self, entry_id: int) -> Optional[VaultEntry]:
        self._require_unlocked()
        row = self._conn.execute(
            "SELECT * FROM entries WHERE id=?", (entry_id,)
        ).fetchone()
        return self._row_to_entry(row) if row else None

    def get_all_entries(self) -> List[VaultEntry]:
        self._require_unlocked()
        rows = self._conn.execute(
            "SELECT * FROM entries ORDER BY site_name COLLATE NOCASE"
        ).fetchall()
        return [self._row_to_entry(r) for r in rows]

    def search_entries(self, query: str) -> List[VaultEntry]:
        """Recherche par nom de site (non chiffré) ou catégorie."""
        self._require_unlocked()
        q = f"%{query.lower()}%"
        rows = self._conn.execute(
            """SELECT * FROM entries
               WHERE LOWER(site_name) LIKE ? OR LOWER(category) LIKE ?
               ORDER BY site_name COLLATE NOCASE""",
            (q, q),
        ).fetchall()
        return [self._row_to_entry(r) for r in rows]

    def get_by_url(self, url: str) -> List[VaultEntry]:
        """Retourne les entrées dont l'URL correspond (pour l'auto-fill)."""
        self._require_unlocked()
        all_entries = self.get_all_entries()
        # Extraction du domaine de l'URL demandée
        try:
            from urllib.parse import urlparse
            domain = urlparse(url).netloc.lstrip("www.")
        except Exception:
            domain = url

        matches = []
        for entry in all_entries:
            try:
                entry_domain = urlparse(entry.site_url).netloc.lstrip("www.")
                if domain and (domain in entry_domain or entry_domain in domain):
                    matches.append(entry)
            except Exception:
                pass
        return matches

    def get_stats(self) -> dict:
        """Statistiques du vault pour le tableau de bord."""
        self._require_unlocked()
        rows = self._conn.execute(
            "SELECT category, COUNT(*) as cnt FROM entries GROUP BY category"
        ).fetchall()
        total = self._conn.execute("SELECT COUNT(*) FROM entries").fetchone()[0]
        favorites = self._conn.execute(
            "SELECT COUNT(*) FROM entries WHERE is_favorite=1"
        ).fetchone()[0]
        meta = self._conn.execute("SELECT * FROM vault_meta").fetchone()

        return {
            "total":       total,
            "favorites":   favorites,
            "by_category": {r["category"]: r["cnt"] for r in rows},
            "created_at":  meta["created_at"],
            "last_sync":   meta["last_accessed_at"],
        }

    # ── Changement du mot de passe maître ───────────────────────────────────

    def change_master_password(self, old_password: str, new_password: str) -> bool:
        """
        Change le mot de passe maître en rechiffrant toutes les entrées.
        Opération atomique : si elle échoue, l'ancien mot de passe reste valide.
        """
        self._require_unlocked()

        # Vérifier l'ancien mot de passe
        row = self._conn.execute("SELECT salt_b64, verification_b64 FROM vault_meta").fetchone()
        old_salt = VaultCrypto.from_b64(row["salt_b64"])
        old_verif = VaultCrypto.from_b64(row["verification_b64"])

        if not verify_master_password(old_password, old_salt, old_verif):
            return False

        # Déchiffrer tout avec l'ancienne clé
        all_entries = self.get_all_entries()

        # Générer un nouveau sel et une nouvelle clé
        new_salt = generate_salt()
        new_crypto = VaultCrypto(new_password, new_salt)
        new_verif = create_verification_blob(new_password, new_salt)

        # Rechiffrer avec la nouvelle clé
        try:
            for entry in all_entries:
                self._conn.execute(
                    """UPDATE entries SET
                       site_url_enc=?, username_enc=?, password_enc=?, notes_enc=?
                       WHERE id=?""",
                    (
                        VaultCrypto.to_b64(new_crypto.encrypt(entry.site_url)),
                        VaultCrypto.to_b64(new_crypto.encrypt(entry.username)),
                        VaultCrypto.to_b64(new_crypto.encrypt(entry.password)),
                        VaultCrypto.to_b64(new_crypto.encrypt(entry.notes or "")),
                        entry.id,
                    ),
                )
            self._conn.execute(
                "UPDATE vault_meta SET salt_b64=?, verification_b64=?, updated_at=?",
                (
                    VaultCrypto.to_b64(new_salt),
                    VaultCrypto.to_b64(new_verif),
                    datetime.now(timezone.utc).isoformat(),
                ),
            )
            self._conn.commit()
            self._crypto = new_crypto
            return True
        except Exception:
            self._conn.rollback()
            raise

    # ── Utilitaires internes ─────────────────────────────────────────────────

    def _create_schema(self) -> None:
        self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS vault_meta (
                version             TEXT NOT NULL,
                salt_b64            TEXT NOT NULL,
                verification_b64    TEXT NOT NULL,
                created_at          TEXT NOT NULL,
                last_accessed_at    TEXT NOT NULL,
                entry_count         INTEGER DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS entries (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                site_name       TEXT NOT NULL,
                site_url_enc    TEXT NOT NULL,
                username_enc    TEXT NOT NULL,
                password_enc    TEXT NOT NULL,
                notes_enc       TEXT NOT NULL DEFAULT '',
                category        TEXT NOT NULL DEFAULT 'Général',
                created_at      TEXT NOT NULL,
                updated_at      TEXT NOT NULL,
                is_favorite     INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_site_name ON entries (site_name COLLATE NOCASE);
            CREATE INDEX IF NOT EXISTS idx_category  ON entries (category);
        """)

    def _enc(self, plaintext: str) -> str:
        return VaultCrypto.to_b64(self._crypto.encrypt(plaintext))

    def _dec(self, b64: str) -> str:
        return self._crypto.decrypt(VaultCrypto.from_b64(b64))

    def _row_to_entry(self, row) -> VaultEntry:
        return VaultEntry(
            id=row["id"],
            site_name=row["site_name"],
            site_url=self._dec(row["site_url_enc"]),
            username=self._dec(row["username_enc"]),
            password=self._dec(row["password_enc"]),
            notes=self._dec(row["notes_enc"]),
            category=row["category"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            is_favorite=bool(row["is_favorite"]),
        )

    def _require_unlocked(self) -> None:
        if not self.is_unlocked or not self._crypto:
            raise PermissionError("Le vault est verrouillé. Appelez vault.unlock() d'abord.")

    def _update_count(self) -> None:
        count = self._conn.execute("SELECT COUNT(*) FROM entries").fetchone()[0]
        self._conn.execute("UPDATE vault_meta SET entry_count=?", (count,))
        self._conn.commit()
