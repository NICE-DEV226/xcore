"""
main.py — Point d'entrée du CLI xcore.

── Groupe dev (créateurs de plugins) ────────────────────────────
    xcore dev validate [path]          Manifeste + scan AST
    xcore dev sign [path] [--key k]    HMAC-SHA256 + Ed25519 en une passe
    xcore dev verify [path] [--key k]  Vérifie la signature locale
    xcore dev login --key <api_key>    Auth sur marketplace.xcore.dev
    xcore dev logout                   Supprime la session locale
    xcore dev whoami                   Compte connecté
    xcore dev submit [path]            Soumet au pipeline 7 gates
    xcore dev status <id>              Progression de la soumission
    xcore dev publish <id>             Publie après approbation

── Groupe plugin (utilisateurs de plugins) ───────────────────────
    xcore plugin install <name>        Installe depuis le marketplace
    xcore plugin remove <name>         Désinstalle
    xcore plugin list                  Liste les plugins installés
    xcore plugin info <name>           Détails d'un plugin
    xcore plugin load <name>           Hot-load sur le serveur
    xcore plugin reload <name>         Hot-reload sur le serveur
    xcore plugin health                Health check de tous les plugins

── Groupe marketplace (navigation) ───────────────────────────────
    xcore marketplace list             Liste les plugins publiés
    xcore marketplace trending         Plugins populaires
    xcore marketplace search <query>   Recherche
    xcore marketplace show <name>      Détails d'un plugin
    xcore marketplace rate <name>      Note un plugin (--score 1-5)

── Autres ────────────────────────────────────────────────────────
    xcore sandbox run|limits|network|fs <name>
    xcore services status
    xcore health
"""

from __future__ import annotations

import asyncio


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(
        prog="xcore",
        description="xcore — framework plugin-first",
    )
    parser.add_argument("--config", default=None, help="Chemin vers xcore.yaml")
    parser.add_argument("--version", action="store_true")

    subparsers = parser.add_subparsers(dest="command")

    # ── dev ───────────────────────────────────────────────────
    dev_p = subparsers.add_parser("dev", help="Créateurs de plugins — validation, signature, publication")
    dev_sub = dev_p.add_subparsers(dest="subcommand")

    dev_val = dev_sub.add_parser("validate", help="Valide le manifeste et scanne l'AST")
    dev_val.add_argument("path", nargs="?", default=".", help="Répertoire du plugin (défaut: .)")
    dev_val.add_argument("--key", default=None, help="Clé HMAC pour vérification signature (optionnel)")
    dev_val.add_argument("--strict", action="store_true", help="Échec si signature absente")

    dev_sign = dev_sub.add_parser("sign", help="Signe le plugin (HMAC + Ed25519)")
    dev_sign.add_argument("path", nargs="?", default=".", help="Répertoire du plugin (défaut: .)")
    dev_sign.add_argument("--key", default=None, help="Clé HMAC locale (défaut: change-me)")
    dev_sign.add_argument("--hub-url", default=None, dest="hub_url")

    dev_ver = dev_sub.add_parser("verify", help="Vérifie la signature locale HMAC")
    dev_ver.add_argument("path", nargs="?", default=".", help="Répertoire du plugin (défaut: .)")
    dev_ver.add_argument("--key", default=None, help="Clé HMAC locale")

    dev_login = dev_sub.add_parser("login", help="Authentifie le compte développeur")
    dev_login.add_argument("--key", required=True, help="API key générée sur marketplace.xcore.dev")
    dev_login.add_argument("--hub-url", default=None, dest="hub_url")

    dev_sub.add_parser("logout", help="Supprime la session locale")
    dev_sub.add_parser("whoami", help="Affiche le compte connecté")

    dev_submit = dev_sub.add_parser("submit", help="Soumet le plugin au pipeline de validation")
    dev_submit.add_argument("path", nargs="?", default=".", help="Répertoire du plugin (défaut: .)")
    dev_submit.add_argument("--key", default=None, help="Clé HMAC pour la signature automatique")
    dev_submit.add_argument("--hub-url", default=None, dest="hub_url")

    dev_status = dev_sub.add_parser("status", help="Progression de la soumission (7 gates)")
    dev_status.add_argument("id", help="ID de soumission")
    dev_status.add_argument("--hub-url", default=None, dest="hub_url")

    dev_publish = dev_sub.add_parser("publish", help="Publie le plugin approuvé")
    dev_publish.add_argument("id", help="ID de soumission approuvée")
    dev_publish.add_argument("--hub-url", default=None, dest="hub_url")

    # ── plugin ────────────────────────────────────────────────
    plugin_p = subparsers.add_parser("plugin", help="Utilisateurs de plugins — installation et gestion")
    plugin_sub = plugin_p.add_subparsers(dest="subcommand")

    install_p = plugin_sub.add_parser("install", help="Installe un plugin depuis le marketplace")
    install_p.add_argument("name")
    install_p.add_argument("--source", choices=["zip", "git", "marketplace"], default="marketplace")
    install_p.add_argument("--url", default=None)

    remove_p = plugin_sub.add_parser("remove", help="Désinstalle un plugin")
    remove_p.add_argument("name")

    plugin_sub.add_parser("list", help="Liste les plugins installés")
    plugin_sub.add_parser("health", help="Health check de tous les plugins")

    info_p = plugin_sub.add_parser("info", help="Affiche les détails d'un plugin")
    info_p.add_argument("name")

    load_p = plugin_sub.add_parser("load", help="Hot-load un plugin sur le serveur")
    load_p.add_argument("name")
    load_p.add_argument("--host", default=None)
    load_p.add_argument("--port", type=int, default=None)
    load_p.add_argument("--path", default=None)
    load_p.add_argument("--key", default=None)

    reload_p = plugin_sub.add_parser("reload", help="Hot-reload un plugin sur le serveur")
    reload_p.add_argument("name")
    reload_p.add_argument("--host", default=None)
    reload_p.add_argument("--port", type=int, default=None)
    reload_p.add_argument("--path", default=None)
    reload_p.add_argument("--key", default=None)

    # ── sandbox ───────────────────────────────────────────────
    sandbox_p = subparsers.add_parser("sandbox", help="Test d'un plugin en sandbox isolé")
    sandbox_sub = sandbox_p.add_subparsers(dest="subcommand")

    sb_run = sandbox_sub.add_parser("run", help="Lance un plugin en sandbox")
    sb_run.add_argument("name")
    sandbox_sub.add_parser("limits",  help="Limites ressources d'un plugin").add_argument("name")
    sandbox_sub.add_parser("network", help="Politique réseau d'un plugin").add_argument("name")
    sandbox_sub.add_parser("fs",      help="Politique filesystem d'un plugin").add_argument("name")

    # ── marketplace ───────────────────────────────────────────
    mkt_p = subparsers.add_parser("marketplace", help="Navigation du catalogue de plugins")
    mkt_sub = mkt_p.add_subparsers(dest="subcommand")

    mkt_sub.add_parser("list",     help="Liste les plugins publiés")
    mkt_sub.add_parser("trending", help="Plugins populaires")

    mkt_search = mkt_sub.add_parser("search", help="Recherche un plugin")
    mkt_search.add_argument("query")

    mkt_show = mkt_sub.add_parser("show", help="Détails d'un plugin")
    mkt_show.add_argument("name")

    mkt_rate = mkt_sub.add_parser("rate", help="Note un plugin (1-5)")
    mkt_rate.add_argument("name")
    mkt_rate.add_argument("--score", type=int, choices=range(1, 6), required=True)

    # ── services / health ─────────────────────────────────────
    svc_p = subparsers.add_parser("services", help="État des services")
    svc_sub = svc_p.add_subparsers(dest="subcommand")
    svc_sub.add_parser("status").add_argument("--json", action="store_true")

    subparsers.add_parser("health", help="Health check global").add_argument("--json", action="store_true")

    # ── Dispatch ──────────────────────────────────────────────
    args = parser.parse_args()

    if args.version:
        from xcore import __version__
        print(f"xcore v{__version__}")
        return

    if args.command == "dev":
        from .dev_cmd import handle_dev
        asyncio.run(handle_dev(args))

    elif args.command == "plugin":
        from .plugin_cmd import handle_plugin
        asyncio.run(handle_plugin(args))

    elif args.command == "sandbox":
        from .sandbox_cmd import handle_sandbox
        asyncio.run(handle_sandbox(args))

    elif args.command == "marketplace":
        from .marketplace_cmd import handle_marketplace
        asyncio.run(handle_marketplace(args))

    elif args.command == "services":
        from .plugin_cmd import handle_services
        asyncio.run(handle_services(args))

    elif args.command == "health":
        from .plugin_cmd import handle_health
        asyncio.run(handle_health(args))

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
