"""
dev_cmd.py — Commandes `xcore dev *` pour les créateurs de plugins.

    xcore dev validate [path]   Valide le manifeste et scanne l'AST
    xcore dev sign [path]       Signe localement (HMAC) + identité marketplace (Ed25519)
    xcore dev verify [path]     Vérifie la signature locale HMAC
    xcore dev login --key <k>   Authentifie le compte développeur via API key
    xcore dev logout            Supprime les credentials locaux
    xcore dev whoami            Affiche le compte connecté
    xcore dev submit [path]     Soumet au pipeline de validation (7 gates)
    xcore dev status <id>       Progression de la soumission
    xcore dev publish <id>      Publie le plugin approuvé
"""

from __future__ import annotations

import json
import sys
import tarfile
import tempfile
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse

from rich.console import Console
from rich.table import Table

console = Console()

AUTH_PATH = Path.home() / ".xcore" / "auth.json"
KEY_PATH  = Path.home() / ".xcore" / "dev.pem"
DEFAULT_HUB = "https://marketplace.xcore.dev"


# ── Helpers ───────────────────────────────────────────────────


def _load_config(args):
    from xcore.configurations.loader import ConfigLoader
    return ConfigLoader.load(getattr(args, "config", None))


def _hub_url(args, cfg) -> str:
    raw = getattr(args, "hub_url", None) or cfg.raw.get("marketplace", {}).get("url") or DEFAULT_HUB
    url = raw.rstrip("/")
    scheme = urlparse(url).scheme
    if scheme not in ("http", "https"):
        console.print(f"[red]Protocole non autorisé : {scheme}[/]")
        sys.exit(1)
    return url


def _read_auth() -> dict:
    if not AUTH_PATH.exists():
        console.print("[red]Non connecté. Lancez : xcore dev login --key <votre-api-key>[/]")
        sys.exit(1)
    try:
        return json.loads(AUTH_PATH.read_text())
    except Exception:
        console.print(f"[red]Fichier auth corrompu : {AUTH_PATH}. Relancez xcore dev login.[/]")
        sys.exit(1)


def _api_headers(auth: dict) -> dict:
    return {
        "Accept": "application/json",
        "X-API-Key": auth["api_key"],
    }


# ── validate ──────────────────────────────────────────────────


async def _dev_validate(args) -> None:
    from xcore.kernel.security.validation import ManifestValidator

    path = Path(getattr(args, "path", ".")).resolve()
    if not path.exists():
        console.print(f"[red]Dossier introuvable : {path}[/]")
        sys.exit(1)
    try:
        manifest = ManifestValidator().load_and_validate(path)
        console.print(f"[green]✅ Manifeste valide[/] — {manifest.name} v{manifest.version} [{manifest.execution_mode.value}]")
    except Exception as e:
        console.print(f"[red]❌ Manifeste invalide : {e}[/]")
        sys.exit(1)


# ── sign ──────────────────────────────────────────────────────


async def _dev_sign(args) -> None:
    """
    Signe le plugin en deux couches :
      1. HMAC-SHA256  (intégrité locale — vérifiable par le serveur xcore)
      2. Ed25519      (identité développeur — vérifiable par le marketplace)
    Les deux signatures sont écrites dans plugin.sig.
    """
    import base64
    from datetime import datetime, timezone

    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import (
            Encoding, NoEncryption, PrivateFormat, PublicFormat, load_pem_private_key,
        )
    except ImportError:
        console.print("[red]Dépendance manquante : pip install cryptography[/]")
        sys.exit(1)

    from xcore.kernel.security.signature import sign_plugin
    from xcore.kernel.security.validation import ManifestValidator

    path = Path(getattr(args, "path", ".")).resolve()
    hmac_key = (getattr(args, "key", None) or "change-me").encode()

    try:
        manifest = ManifestValidator().load_and_validate(path)
    except Exception as e:
        console.print(f"[red]Manifeste invalide : {e}[/]")
        sys.exit(1)

    # 1. HMAC-SHA256 (intégrité locale)
    sig_path = sign_plugin(manifest, hmac_key)
    hmac_data = json.loads(sig_path.read_text())
    console.print(f"[dim]HMAC-SHA256 calculé[/]")

    # 2. Ed25519 (identité marketplace)
    KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
    if not KEY_PATH.exists():
        private_key = Ed25519PrivateKey.generate()
        KEY_PATH.write_bytes(
            private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
        )
        KEY_PATH.chmod(0o600)
        console.print(f"[green]Clé Ed25519 générée → {KEY_PATH}[/]")
    else:
        loaded = load_pem_private_key(KEY_PATH.read_bytes(), password=None)
        if not isinstance(loaded, Ed25519PrivateKey):
            console.print(f"[red]Clé dans {KEY_PATH} n'est pas Ed25519. Supprimez-la pour en régénérer une.[/]")
            sys.exit(1)
        private_key = loaded

    pub_bytes = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    pub_hex   = pub_bytes.hex()
    dev_id    = f"did:xcore:dev-{pub_hex[:16]}"

    payload   = f"{dev_id}:{hmac_data['digest']}".encode()
    signature = private_key.sign(payload)
    sig_b64   = base64.b64encode(signature).decode()

    # Fusion des deux signatures dans plugin.sig
    sig_bundle = {
        **hmac_data,
        "format": "xcore-sig-v2",
        "developer": {
            "id": dev_id,
            "public_key": pub_hex,
            "signature": sig_b64,
            "algo": "Ed25519",
        },
        "issued_at": datetime.now(timezone.utc).isoformat(),
    }
    sig_path.write_text(json.dumps(sig_bundle, indent=2))

    console.print(f"[green]✅ Plugin signé[/] → {sig_path}")
    console.print(f"   Identité : [cyan]{dev_id}[/]")


# ── verify ────────────────────────────────────────────────────


async def _dev_verify(args) -> None:
    from xcore.kernel.security.signature import SignatureError, verify_plugin
    from xcore.kernel.security.validation import ManifestValidator

    path = Path(getattr(args, "path", ".")).resolve()
    key  = (getattr(args, "key", None) or "change-me").encode()

    try:
        manifest = ManifestValidator().load_and_validate(path)
        verify_plugin(manifest, key)
        console.print(f"[green]✅ Signature valide[/] — {manifest.name}")
    except Exception as e:
        console.print(f"[red]❌ {e}[/]")
        sys.exit(1)


# ── login ─────────────────────────────────────────────────────


async def _dev_login(args) -> None:
    import urllib.request

    api_key = getattr(args, "key", None)
    if not api_key:
        console.print("[red]--key requis. Générez une API key sur marketplace.xcore.dev.[/]")
        sys.exit(1)

    cfg = _load_config(args)
    hub = _hub_url(args, cfg)

    console.print(f"[cyan]Vérification de la clé sur {hub}...[/]")
    try:
        req = urllib.request.Request(
            f"{hub}/auth/me",
            headers={"Accept": "application/json", "X-API-Key": api_key},
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            identity = json.loads(resp.read().decode())
    except HTTPError as e:
        if e.code == 401:
            console.print("[red]❌ API key invalide.[/]")
        else:
            console.print(f"[red]HTTP {e.code}[/]")
        sys.exit(1)
    except URLError as e:
        console.print(f"[red]Connexion impossible : {e.reason}[/]")
        sys.exit(1)

    AUTH_PATH.parent.mkdir(parents=True, exist_ok=True)
    AUTH_PATH.write_text(json.dumps({
        "api_key":    api_key,
        "username":   identity.get("username", "?"),
        "email":      identity.get("email", "?"),
        "hub_url":    hub,
    }, indent=2))
    AUTH_PATH.chmod(0o600)

    console.print(f"[green]✅ Connecté en tant que[/] [cyan]{identity.get('username', '?')}[/] ({identity.get('email', '?')})")


# ── logout ────────────────────────────────────────────────────


async def _dev_logout(args) -> None:
    if AUTH_PATH.exists():
        AUTH_PATH.unlink()
        console.print("[green]Déconnecté.[/]")
    else:
        console.print("[yellow]Aucune session active.[/]")


# ── whoami ────────────────────────────────────────────────────


async def _dev_whoami(args) -> None:
    auth = _read_auth()
    console.print(f"[bold]{auth.get('username', '?')}[/] — {auth.get('email', '?')}")
    console.print(f"[dim]Hub : {auth.get('hub_url', DEFAULT_HUB)}[/]")


# ── submit ────────────────────────────────────────────────────


async def _dev_submit(args) -> None:
    import urllib.request

    auth = _read_auth()
    cfg  = _load_config(args)
    hub  = _hub_url(args, cfg)

    plugin_path = Path(getattr(args, "path", ".")).resolve()
    if not (plugin_path / "plugin.yaml").exists() and not (plugin_path / "plugin.json").exists():
        console.print(f"[red]Aucun plugin.yaml dans {plugin_path}[/]")
        sys.exit(1)

    # Auto-signe si plugin.sig absent ou ne contient pas Ed25519
    sig_path = plugin_path / "plugin.sig"
    needs_sign = True
    if sig_path.exists():
        try:
            sig_data = json.loads(sig_path.read_text())
            if "developer" in sig_data:
                needs_sign = False
        except Exception:
            pass

    if needs_sign:
        console.print("[yellow]plugin.sig absent ou incomplet — signature automatique...[/]")
        await _dev_sign(args)

    with tempfile.NamedTemporaryFile(suffix=".tar.gz", delete=False) as tmp:
        tmp_path = Path(tmp.name)

    with tarfile.open(tmp_path, "w:gz") as tar:
        tar.add(plugin_path, arcname=".")

    size_kb = tmp_path.stat().st_size // 1024
    console.print(f"[cyan]📦 Archive {size_kb} KB → {hub}/submissions/[/]")

    try:
        boundary = "----XCoreDevSubmit"
        with open(tmp_path, "rb") as f:
            file_data = f.read()

        body = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="archive"; filename="plugin.tar.gz"\r\n'
            f"Content-Type: application/gzip\r\n\r\n"
        ).encode() + file_data + f"\r\n--{boundary}--\r\n".encode()

        req = urllib.request.Request(
            f"{hub}/submissions/",
            data=body,
            method="POST",
            headers={
                "Content-Type": f"multipart/form-data; boundary={boundary}",
                **_api_headers(auth),
            },
        )
        with urllib.request.urlopen(req, timeout=60) as resp:
            data = json.loads(resp.read().decode())

    except HTTPError as e:
        console.print(f"[red]HTTP {e.code} : {e.read().decode('utf-8', errors='replace')}[/]")
        tmp_path.unlink(missing_ok=True)
        sys.exit(1)
    except URLError as e:
        console.print(f"[red]Connexion impossible : {e.reason}[/]")
        tmp_path.unlink(missing_ok=True)
        sys.exit(1)
    finally:
        tmp_path.unlink(missing_ok=True)

    sid = data.get("submission_id", "?")
    console.print(f"\n[green]✅ Soumis ![/]  Plugin : [cyan]{data.get('plugin', '?')} v{data.get('version', '?')}[/]")
    console.print(f"   ID : [yellow]{sid}[/]")
    console.print(f"   Suivi : [bold]xcore dev status {sid}[/]")


# ── status ────────────────────────────────────────────────────


async def _dev_status(args) -> None:
    import urllib.request

    cfg = _load_config(args)
    hub = _hub_url(args, cfg)
    sid = args.id

    try:
        req = urllib.request.Request(
            f"{hub}/submissions/{sid}",
            headers={"Accept": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
    except HTTPError as e:
        console.print(f"[red]{'Soumission introuvable' if e.code == 404 else f'HTTP {e.code}'}[/]")
        sys.exit(1)
    except URLError as e:
        console.print(f"[red]Connexion impossible : {e.reason}[/]")
        sys.exit(1)

    status = data.get("status", "?")
    color  = {"pending": "yellow", "approved": "green", "rejected": "red", "published": "bright_green"}.get(status, "white")

    console.print(f"\n[bold]{data.get('plugin', '?')} v{data.get('version', '?')}[/]  [{color}]{status.upper()}[/{color}]  score: {data.get('anomaly_score', 0)}")

    gates = data.get("gates", [])
    if gates:
        table = Table(show_header=True, header_style="bold dim")
        table.add_column("Gate")
        table.add_column("Statut", justify="center")
        table.add_column("Score",  justify="right")
        table.add_column("Durée",  justify="right")
        icons = {"passed": "✅", "failed": "❌", "blocked": "🚫", "pending": "⏳", "running": "🔄"}
        for g in gates:
            s = g.get("status", "pending")
            table.add_row(g.get("gate", "?"), f"{icons.get(s, '?')} {s}", str(g.get("anomaly_score", 0)), f"{g.get('duration_seconds', 0):.1f}s")
        console.print(table)

    if status == "approved":
        console.print(f"\n   Publier : [bold]xcore dev publish {sid}[/]")


# ── publish ───────────────────────────────────────────────────


async def _dev_publish(args) -> None:
    import urllib.request

    auth = _read_auth()
    cfg  = _load_config(args)
    hub  = _hub_url(args, cfg)
    sid  = args.id

    try:
        req = urllib.request.Request(
            f"{hub}/submissions/{sid}/publish",
            data=b"{}",
            method="POST",
            headers={"Content-Type": "application/json", **_api_headers(auth)},
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode())
    except HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        try:
            detail = json.loads(body).get("detail", body)
        except Exception:
            detail = body
        console.print(f"[red]HTTP {e.code} : {detail}[/]")
        sys.exit(1)
    except URLError as e:
        console.print(f"[red]Connexion impossible : {e.reason}[/]")
        sys.exit(1)

    name = data.get("plugin_name", "?")
    ver  = data.get("version", "?")
    console.print(f"[green]✅ {name} v{ver} publié ![/]  {hub}/plugins/{name}")


# ── dispatcher ────────────────────────────────────────────────


async def handle_dev(args) -> None:
    sub = getattr(args, "subcommand", None)
    dispatch = {
        "validate": _dev_validate,
        "sign":     _dev_sign,
        "verify":   _dev_verify,
        "login":    _dev_login,
        "logout":   _dev_logout,
        "whoami":   _dev_whoami,
        "submit":   _dev_submit,
        "status":   _dev_status,
        "publish":  _dev_publish,
    }
    handler = dispatch.get(sub)
    if handler:
        await handler(args)
    else:
        console.print("Usage : xcore dev <validate|sign|verify|login|logout|whoami|submit|status|publish>")
