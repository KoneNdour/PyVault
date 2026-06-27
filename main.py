#!/usr/bin/env python3
"""
main.py — Point d'entrée de PyVault
=====================================
Lance le serveur Flask local et ouvre l'interface dans le navigateur par défaut.

Usage :
    python main.py           # Lance avec interface navigateur
    python main.py --no-browser  # Lance en mode serveur seulement
    python main.py --port 8080   # Utilise un port personnalisé
"""

import sys
import argparse


def main():
    parser = argparse.ArgumentParser(description="PyVault — Gestionnaire de mots de passe")
    parser.add_argument("--no-browser", action="store_true", help="Ne pas ouvrir le navigateur au démarrage")
    parser.add_argument("--port", type=int, default=7890, help="Port du serveur local (défaut: 7890)")
    args = parser.parse_args()

    # Injection du port si modifié
    import app.server as server
    server.PORT = args.port

    try:
        server.start_server(open_browser=not args.no_browser)
    except KeyboardInterrupt:
        print("\n[PyVault] Arrêt du serveur.")
        sys.exit(0)
    except OSError as e:
        if "Address already in use" in str(e):
            print(f"\n[Erreur] Le port {args.port} est déjà utilisé.")
            print(f"Essayez : python main.py --port {args.port + 1}")
        else:
            raise


if __name__ == "__main__":
    main()
