"""
core/crypto.py — Module de cryptographie de PyVault
=====================================================
Dérivation de clé : Argon2id (résistant aux GPU et side-channels)
Chiffrement      : AES-256-GCM (authenticated encryption)
Intégrité        : tag GCM 16 octets inclus dans chaque ciphertext
"""

import os
import base64
import struct
import secrets
from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ── Paramètres Argon2id (OWASP 2023 recommandations) ─────────────────────────
ARGON2_TIME_COST    = 3        # 3 itérations
ARGON2_MEMORY_COST  = 65536    # 64 MiB
ARGON2_PARALLELISM  = 4        # 4 threads
ARGON2_HASH_LEN     = 32       # 256 bits → clé AES-256
ARGON2_SALT_LEN     = 32       # 256 bits de sel

# ── Format d'un ciphertext : IV[12] || TAG[16] || CIPHERTEXT ─────────────────
IV_LEN  = 12   # Nonce GCM recommandé par NIST
TAG_LEN = 16   # Tag d'authentification GCM


class VaultCrypto:
    """
    Gestion complète des opérations cryptographiques du vault.

    Flux de dérivation :
        master_password + salt ──[Argon2id]──► 256-bit key
        
    Flux de chiffrement (par champ) :
        plaintext ──[AES-256-GCM, IV aléatoire]──► IV || ciphertext+tag
    """

    def __init__(self, master_password: str, salt: bytes):
        """
        Dérive la clé AES depuis le mot de passe maître.
        Le sel est fourni externement pour être stocké avec le vault.
        """
        key_bytes = hash_secret_raw(
            secret=master_password.encode("utf-8"),
            salt=salt,
            time_cost=ARGON2_TIME_COST,
            memory_cost=ARGON2_MEMORY_COST,
            parallelism=ARGON2_PARALLELISM,
            hash_len=ARGON2_HASH_LEN,
            type=Type.ID,
        )
        self._aesgcm = AESGCM(key_bytes)

    # ── Chiffrement ──────────────────────────────────────────────────────────

    def encrypt(self, plaintext: str, aad: bytes = b"") -> bytes:
        """
        Chiffre une chaîne en texte clair.
        
        Retourne : IV[12] || Ciphertext+Tag
        Le tag GCM est automatiquement inclus dans le ciphertext par la lib.
        aad : Additional Authenticated Data (non chiffré mais authentifié)
        """
        iv = secrets.token_bytes(IV_LEN)
        ct = self._aesgcm.encrypt(iv, plaintext.encode("utf-8"), aad or None)
        return iv + ct  # IV en clair préfixé (nécessaire pour le déchiffrement)

    def decrypt(self, ciphertext_blob: bytes, aad: bytes = b"") -> str:
        """
        Déchiffre un blob produit par encrypt().
        Lève cryptography.exceptions.InvalidTag si le blob est corrompu ou forgé.
        """
        iv  = ciphertext_blob[:IV_LEN]
        ct  = ciphertext_blob[IV_LEN:]
        return self._aesgcm.decrypt(iv, ct, aad or None).decode("utf-8")

    # ── Sérialisation (stockage en base) ─────────────────────────────────────

    @staticmethod
    def to_b64(blob: bytes) -> str:
        """Encode un blob en Base64 URL-safe pour stockage SQLite."""
        return base64.urlsafe_b64encode(blob).decode("ascii")

    @staticmethod
    def from_b64(s: str) -> bytes:
        """Décode depuis Base64 URL-safe."""
        return base64.urlsafe_b64decode(s.encode("ascii"))


# ── Utilitaires indépendants de la clé ───────────────────────────────────────

def generate_salt() -> bytes:
    """Génère un sel cryptographique aléatoire (32 octets)."""
    return secrets.token_bytes(ARGON2_SALT_LEN)


def verify_master_password(master_password: str, salt: bytes, verification_blob: bytes) -> bool:
    """
    Vérifie le mot de passe maître en tentant de déchiffrer un blob de vérification connu.
    Retourne True si le mot de passe est correct, False sinon.
    """
    try:
        crypto = VaultCrypto(master_password, salt)
        result = crypto.decrypt(verification_blob)
        return result == "PYVAULT_OK"
    except Exception:
        return False


def create_verification_blob(master_password: str, salt: bytes) -> bytes:
    """
    Crée le blob de vérification stocké dans le vault header.
    Permet de valider le mot de passe maître sans stocker le mot de passe lui-même.
    """
    crypto = VaultCrypto(master_password, salt)
    return crypto.encrypt("PYVAULT_OK")
