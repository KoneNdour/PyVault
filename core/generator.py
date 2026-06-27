"""
core/generator.py — Générateur de mots de passe cryptographiquement sûr
=========================================================================
Utilise secrets.choice() qui repose sur os.urandom() (CSPRNG du système).
"""

import secrets
import string
import re
from dataclasses import dataclass


@dataclass
class PasswordPolicy:
    """Politique de génération d'un mot de passe."""
    length: int          = 20
    use_uppercase: bool  = True
    use_lowercase: bool  = True
    use_digits: bool     = True
    use_symbols: bool    = True
    exclude_ambiguous: bool = True   # Exclut 0,O,l,I,1
    custom_symbols: str  = "!@#$%^&*()-_=+[]{}|;:,.<>?"
    min_uppercase: int   = 1
    min_lowercase: int   = 1
    min_digits: int      = 1
    min_symbols: int     = 1


# Caractères ambigus à exclure optionnellement
AMBIGUOUS = set("0O1lI|`\"'\\")


def generate_password(policy: PasswordPolicy = None) -> str:
    """
    Génère un mot de passe selon la politique fournie.
    Garantit la présence des catégories minimales demandées.
    """
    if policy is None:
        policy = PasswordPolicy()

    # Construire l'alphabet
    alphabet = ""
    mandatory = []

    if policy.use_lowercase:
        chars = string.ascii_lowercase
        if policy.exclude_ambiguous:
            chars = "".join(c for c in chars if c not in AMBIGUOUS)
        alphabet += chars
        for _ in range(policy.min_lowercase):
            mandatory.append(secrets.choice(chars))

    if policy.use_uppercase:
        chars = string.ascii_uppercase
        if policy.exclude_ambiguous:
            chars = "".join(c for c in chars if c not in AMBIGUOUS)
        alphabet += chars
        for _ in range(policy.min_uppercase):
            mandatory.append(secrets.choice(chars))

    if policy.use_digits:
        chars = string.digits
        if policy.exclude_ambiguous:
            chars = "".join(c for c in chars if c not in AMBIGUOUS)
        alphabet += chars
        for _ in range(policy.min_digits):
            mandatory.append(secrets.choice(chars))

    if policy.use_symbols:
        chars = policy.custom_symbols
        if policy.exclude_ambiguous:
            chars = "".join(c for c in chars if c not in AMBIGUOUS)
        alphabet += chars
        for _ in range(policy.min_symbols):
            mandatory.append(secrets.choice(chars))

    if not alphabet:
        raise ValueError("L'alphabet est vide : activez au moins une catégorie de caractères.")

    # Compléter jusqu'à la longueur souhaitée
    remaining = policy.length - len(mandatory)
    if remaining < 0:
        raise ValueError(f"La longueur minimale requise ({len(mandatory)}) dépasse la longueur demandée ({policy.length}).")

    password_chars = mandatory + [secrets.choice(alphabet) for _ in range(remaining)]

    # Mélanger pour éviter que les caractères obligatoires soient en début
    secrets.SystemRandom().shuffle(password_chars)

    return "".join(password_chars)


def estimate_entropy(password: str) -> dict:
    """
    Estime l'entropie d'un mot de passe en bits.
    Retourne un dict avec l'entropie et le niveau de force.
    """
    has_lower   = bool(re.search(r"[a-z]", password))
    has_upper   = bool(re.search(r"[A-Z]", password))
    has_digit   = bool(re.search(r"\d", password))
    has_symbol  = bool(re.search(r"[^a-zA-Z0-9]", password))

    pool = 0
    if has_lower:   pool += 26
    if has_upper:   pool += 26
    if has_digit:   pool += 10
    if has_symbol:  pool += 32  # estimation

    import math
    entropy = len(password) * math.log2(pool) if pool > 0 else 0

    if entropy >= 128:
        strength = "Très fort"
        color    = "#27ae60"
    elif entropy >= 80:
        strength = "Fort"
        color    = "#2980b9"
    elif entropy >= 50:
        strength = "Moyen"
        color    = "#f39c12"
    else:
        strength = "Faible"
        color    = "#e74c3c"

    return {
        "entropy_bits": round(entropy, 1),
        "strength":     strength,
        "color":        color,
        "length":       len(password),
        "has_lower":    has_lower,
        "has_upper":    has_upper,
        "has_digit":    has_digit,
        "has_symbol":   has_symbol,
    }


def check_password_breach(password: str) -> dict:
    """
    Vérifie si le mot de passe est dans la base HIBP (Have I Been Pwned)
    via l'API k-anonymity (seulement les 5 premiers caractères du SHA-1 sont envoyés).
    """
    import hashlib
    import requests

    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix = sha1[:5]
    suffix = sha1[5:]

    try:
        resp = requests.get(
            f"https://api.pwnedpasswords.com/range/{prefix}",
            timeout=5,
            headers={"User-Agent": "PyVault-HIBP-Check/1.0"}
        )
        if resp.status_code == 200:
            for line in resp.text.splitlines():
                h, count = line.split(":")
                if h == suffix:
                    return {"pwned": True, "count": int(count)}
        return {"pwned": False, "count": 0}
    except Exception:
        return {"pwned": None, "count": 0, "error": "Service non disponible"}
