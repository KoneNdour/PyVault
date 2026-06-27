<div align="center">

# 🔒 PyVault

### Gestionnaire de mots de passe local, sécurisé et open-source

[![Python 3.10+](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![AES-256-GCM](https://img.shields.io/badge/Chiffrement-AES--256--GCM-27AE60?style=for-the-badge&logo=shield&logoColor=white)](/)
[![Argon2id](https://img.shields.io/badge/KDF-Argon2id-8E44AD?style=for-the-badge)](/)
[![Chrome Extension](https://img.shields.io/badge/Extension-Chrome-4285F4?style=for-the-badge&logo=googlechrome&logoColor=white)](/)
[![GitHub Backup](https://img.shields.io/badge/Backup-GitHub-181717?style=for-the-badge&logo=github&logoColor=white)](/)
[![License MIT](https://img.shields.io/badge/License-MIT-F39C12?style=for-the-badge)](LICENSE)

**PyVault** est un gestionnaire de mots de passe 100 % local construit en Python.  
Vos mots de passe ne quittent jamais votre machine — seul un fichier chiffré est synchronisé sur GitHub.

[🚀 Démarrage rapide](#-démarrage-rapide) · [🧩 Extension Chrome](#-extension-chrome) · [☁️ Backup GitHub](#️-backup-github) · [🛡️ Sécurité](#️-architecture-de-sécurité)

</div>

---

## 🎯 Pourquoi PyVault ?

La plupart des gestionnaires cloud (LastPass, 1Password) stockent vos données sur leurs serveurs.  
**PyVault adopte l'approche inverse** : tout reste chiffré localement, et seul le coffre chiffré (inutilisable sans votre mot de passe maître) est sauvegardé en ligne.

```
Votre machine                           GitHub (backup)
┌─────────────────────────────────┐     ┌──────────────────┐
│  vault.db                       │────►│  vault.db (enc.) │
│  ├── entrée 1 [AES-256-GCM]    │     │  (inutilisable   │
│  ├── entrée 2 [AES-256-GCM]    │     │   sans le MDP    │
│  └── ...                        │     │   maître)        │
│                                 │     └──────────────────┘
│  Mot de passe maître            │
│  ──[Argon2id]──► Clé AES ──►   │     ❌ La clé n'est
│                   Déchiffrement │        JAMAIS envoyée
└─────────────────────────────────┘
```

---

## ✨ Fonctionnalités

| Fonctionnalité | Description |
|---|---|
| 🔐 **AES-256-GCM** | Chaque mot de passe chiffré individuellement avec un IV aléatoire |
| 🧂 **Argon2id** | Dérivation de clé résistante aux GPU/ASICs (recommandé OWASP 2023) |
| 🌐 **Extension Chrome** | Auto-fill sur les formulaires de connexion |
| ⚡ **Générateur CSPRNG** | `secrets.choice()` + vérification HIBP (Have I Been Pwned) |
| ☁️ **Backup GitHub** | Seul le vault chiffré est poussé, la clé reste locale |
| 🖥️ **Interface web** | SPA moderne sur `http://127.0.0.1:7890` |

---

## 🛡️ Architecture de sécurité

```
┌──────────────────────────────────────────────────────────────┐
│                   DÉRIVATION DE CLÉ                          │
│                                                               │
│  Mot de passe maître  ──► Argon2id ──► Clé AES-256 (32o)   │
│  (jamais stocké)          t=3, m=64MiB, p=4 threads          │
│                           sel=256 bits (stocké vault.db)     │
└──────────────────────────────────────────────────────────────┘
                               │
                               ▼
┌──────────────────────────────────────────────────────────────┐
│                  CHIFFREMENT (par champ)                      │
│                                                               │
│  Texte clair ──► AES-256-GCM ──► IV[12] + CipherText + Tag  │
│                   IV aléatoire (SecureRandom, jamais réutilisé)│
│                   Tag 128 bits (intégrité authentifiée)       │
└──────────────────────────────────────────────────────────────┘
```

| Composant | Algorithme | Paramètres |
|---|---|---|
| Dérivation de clé | Argon2id | t=3, m=65 536 KiB, p=4 |
| Chiffrement | AES-256-GCM | Clé 256 bits, IV 96 bits, Tag 128 bits |
| Sel | `os.urandom()` | 256 bits |
| IV / Nonce | `secrets.token_bytes()` | 96 bits, unique par champ |
| Génération de mots de passe | `secrets.choice()` | CSPRNG du système |
| Token de session | `secrets.token_hex(32)` | 256 bits, régénéré au démarrage |

---

## 🚀 Démarrage rapide

**Prérequis :** Python 3.10+ · Google Chrome

```bash
# 1. Cloner
git clone https://github.com/VOTRE_USERNAME/pyvault.git
cd pyvault

# 2. Installer les dépendances
pip install -r requirements.txt

# 3. Lancer
python main.py
```

L'interface s'ouvre sur **http://127.0.0.1:7890**. Créez votre vault avec un mot de passe maître robuste (≥ 12 caractères). **Ce mot de passe ne peut pas être récupéré en cas d'oubli** — c'est la garantie de sécurité.

---

## 🧩 Extension Chrome

```
1. chrome://extensions → Mode développeur (activer)
2. "Charger l'extension non empaquetée" → sélectionner  extension/
3. PyVault → Paramètres → copier le token de session
4. Coller le token dans les paramètres de l'extension
```

Quand vous visitez un site enregistré dans votre vault, une bannière apparaît automatiquement pour remplir les champs identifiant/mot de passe.

---

## ☁️ Backup GitHub

> **Seul `vault.db` chiffré est envoyé. Sans le mot de passe maître, ce fichier est inutilisable.**

```
1. Créer un dépôt PRIVÉ sur GitHub
2. Settings → Developer settings → Personal access tokens
   Permissions : repo (accès complet)
3. PyVault → onglet "Sync GitHub" → renseigner token + username + repo
4. Cliquer sur "Pousser vers GitHub"
```

**Restauration :**
```bash
python main.py
# Sync → "Restaurer depuis GitHub" → entrer votre mot de passe maître
```

---

## 📁 Structure

```
pyvault/
├── core/
│   ├── crypto.py        # Argon2id + AES-256-GCM
│   ├── vault.py         # Base SQLite chiffrée
│   ├── generator.py     # Générateur + HIBP
│   └── github_sync.py   # Backup GitHub API
├── app/
│   ├── server.py        # API REST Flask locale
│   └── templates/
│       └── index.html   # Interface web (SPA)
├── extension/           # Extension Chrome (Manifest V3)
│   ├── manifest.json
│   ├── popup.html
│   ├── background.js
│   └── content.js
├── main.py
└── requirements.txt
```

---

## 🔒 Modèle de sécurité

- ✅ Mots de passe jamais stockés en clair
- ✅ Mot de passe maître jamais sauvegardé ni transmis
- ✅ Serveur Flask sur `127.0.0.1` uniquement (pas d'accès réseau)
- ✅ Token de session régénéré à chaque démarrage
- ✅ Altération d'un champ détectée par le tag GCM
- ✅ Backup GitHub : données chiffrées uniquement

---

## 📦 Dépendances

| Paquet | Usage |
|---|---|
| `cryptography` | AES-256-GCM |
| `argon2-cffi` | Argon2id |
| `flask` + `flask-cors` | Serveur local + extension |
| `requests` | GitHub API + HIBP |

---

## 🤝 Contribuer

Fork → Clone → Branche feature → Pull Request. Toutes les contributions sont les bienvenues !

---

## 📄 Licence

MIT © 2026

---

<div align="center">
R�alisé dans le cadre du Master 1 SSI — ESP Dakar<br>
Cours : Programmation Sécurisée DevSecOps — Enseignant : Doudou FALL<br><br>
<em>Si ce projet vous a été utile, une ⭐ sur GitHub est appréciée !</em>
</div>
