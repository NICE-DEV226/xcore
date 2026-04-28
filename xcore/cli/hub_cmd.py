"""
hub_cmd.py — Commandes `xcore hub *` pour la publication sur marketplace.xcore.dev.

    xcore hub sign              Génère/réutilise la clé Ed25519 et signe le plugin
    xcore hub submit  [path]    Soumet le plugin au pipeline de validation (7 gates)
    xcore hub status  <id>      Affiche la progression de la soumission
    xcore hub publish <id>      Publie le plugin après approbation
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

KEY_PATH = Path.home() / ".xcore" / "dev.pem"
DEFAULT_HUB = "https://marketplace.xcore.dev"


def _hub_url(args, cfg) -> str:
    raw = getattr(args, "hub_url", None) or cfg.raw.get("marketplace", {}).get("url") or DEFAULT_HUB
    url = raw.rstrip("/")
    scheme = urlparse(url).scheme
    if scheme not in ("http", "https"):
        console.print(f"[red]Protocole non autorisé : {scheme}[/]")
        sys.exit(1)
    return url


def _load_config(args):
    from xcore.configurations.loader import ConfigLoader
    return ConfigLoader.load(getattr(args, "config", None))


# ── sign ──────────────────────────────────────────────────────


async def _hub_sign(args) -> None:
    """
    Génère une paire de clés Ed25519 dans ~/.xcore/dev.pem (une seule fois),
    puis signe le plugin courant avec l'identité développeur.

    Le fichier plugin.sig résultant contient un SigBundle v2 (format marketplace)
    — différent du HMAC-SHA256 de `xcore plugin sign` (intégrité locale).
    """
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import (
            Encoding, NoEncryption, PrivateFormat, PublicFormat,
        )
    except ImportError:
        console.print("[red]Dépendance manquante : pip install cryptography[/]")
        sys.exit(1)

    plugin_path = Path(getattr(args, "path", ".")).resolve()
    if not (plugin_path / "plugin.yaml").exists() and not (plugin_path / "plugin.json").exists():
        console.print(f"[red]Aucun plugin.yaml trouvé dans {plugin_path}[/]")
        sys.exit(1)

    # Génère la clé si elle n'existe pas encore
    KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
    if not KEY_PATH.exists():
        private_key = Ed25519PrivateKey.generate()
        KEY_PATH.write_bytes(
            private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
        )
        KEY_PATH.chmod(0o600)
        console.print(f"[green]Clé Ed25519 générée → {KEY_PATH}[/]")
    else:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import load_pem_private_key
        loaded = load_pem_private_key(KEY_PATH.read_bytes(), password=None)
        if not isinstance(loaded, Ed25519PrivateKey):
            console.print(f"[red]Clé dans {KEY_PATH} n'est pas Ed25519. Supprimez-la pour en générer une nouvelle.[/]")
            sys.exit(1)
        private_key = loaded

    pub_bytes = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    pub_hex = pub_bytes.hex()
    dev_id = f"did:xcore:dev-{pub_hex[:16]}"

    # Calcule le digest du plugin (Merkle root)
    try:
        from xcore_core.merkle import compute_merkle_root
        digest = compute_merkle_root(plugin_path)
    except ImportError:
        import hashlib
        # Fallback simple si xcore_core n'est pas disponible
        h = hashlib.sha256()
        for f in sorted(plugin_path.rglob("*")):
            if f.is_file() and f.name not in ("plugin.sig",):
                h.update(f.read_bytes())
        digest = h.hexdigest()

    # Signe
    import base64
    from datetime import datetime, timezone
    payload = f"{dev_id}:{digest}".encode()
    signature = private_key.sign(payload)
    sig_b64 = base64.b64encode(signature).decode()

    sig_bundle = {
        "format": "xcore-sig-v2",
        "subject": {"digest": digest},
        "developer": {
            "id": dev_id,
            "public_key": pub_hex,
            "signature": sig_b64,
            "algo": "Ed25519",
        },
        "issued_at": datetime.now(timezone.utc).isoformat(),
    }

    sig_path = plugin_path / "plugin.sig"
    sig_path.write_text(json.dumps(sig_bundle, indent=2))
    console.print(f"[green]✅ Signé[/] → {sig_path}")
    console.print(f"   Identité : [cyan]{dev_id}[/]")


# ── submit ────────────────────────────────────────────────────


async def _hub_submit(args) -> None:
    """
    Signe automatiquement si plugin.sig manque, puis soumet au pipeline xcore-hub.
    """
    import urllib.request

    cfg = _load_config(args)
    plugin_path = Path(getattr(args, "path", ".")).resolve()

    if not (plugin_path / "plugin.yaml").exists() and not (plugin_path / "plugin.json").exists():
        console.print(f"[red]Aucun plugin.yaml trouvé dans {plugin_path}[/]")
        sys.exit(1)

    # Auto-sign si plugin.sig absent
    if not (plugin_path / "plugin.sig").exists():
        console.print("[yellow]plugin.sig absent — signature automatique...[/]")
        await _hub_sign(args)

    hub = _hub_url(args, cfg)

    # Archive .tar.gz
    with tempfile.NamedTemporaryFile(suffix=".tar.gz", delete=False) as tmp:
        tmp_path = Path(tmp.name)

    with tarfile.open(tmp_path, "w:gz") as tar:
        tar.add(plugin_path, arcname=".")

    size_kb = tmp_path.stat().st_size // 1024
    console.print(f"[cyan]📦 Archive {size_kb} KB → {hub}/submissions/[/]")

    try:
        boundary = "----XCoreHubBoundary7gates"
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
            headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
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
    console.print(f"\n[green]✅ Soumis ![/]")
    console.print(f"   Plugin : [cyan]{data.get('plugin', '?')} v{data.get('version', '?')}[/]")
    console.print(f"   ID     : [yellow]{sid}[/]")
    console.print(f"\n   Suivre : [bold]xcore hub status {sid}[/]")


# ── status ────────────────────────────────────────────────────


async def _hub_status(args) -> None:
    import urllib.request

    cfg = _load_config(args)
    sid = args.id
    hub = _hub_url(args, cfg)

    try:
        req = urllib.request.Request(
            f"{hub}/submissions/{sid}",
            headers={"Accept": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
    except HTTPError as e:
        if e.code == 404:
            console.print(f"[red]Soumission introuvable : {sid}[/]")
        else:
            console.print(f"[red]HTTP {e.code}[/]")
        sys.exit(1)
    except URLError as e:
        console.print(f"[red]Connexion impossible : {e.reason}[/]")
        sys.exit(1)

    status = data.get("status", "?")
    color = {"pending": "yellow", "approved": "green", "rejected": "red", "published": "bright_green"}.get(status, "white")

    console.print(f"\n[bold]{data.get('plugin', '?')} v{data.get('version', '?')}[/]  [{color}]{status.upper()}[/{color}]  score: {data.get('anomaly_score', 0)}")

    gates = data.get("gates", [])
    if gates:
        table = Table(show_header=True, header_style="bold dim")
        table.add_column("Gate")
        table.add_column("Statut", justify="center")
        table.add_column("Score", justify="right")
        table.add_column("Durée", justify="right")

        icons = {"passed": "✅", "failed": "❌", "blocked": "🚫", "pending": "⏳", "running": "🔄"}
        for g in gates:
            s = g.get("status", "pending")
            table.add_row(
                g.get("gate", "?"),
                f"{icons.get(s, '?')} {s}",
                str(g.get("anomaly_score", 0)),
                f"{g.get('duration_seconds', 0):.1f}s",
            )
        console.print(table)

    if status == "approved":
        console.print(f"\n   Publier : [bold]xcore hub publish {sid}[/]")


# ── publish ───────────────────────────────────────────────────


async def _hub_publish(args) -> None:
    import urllib.request

    cfg = _load_config(args)
    sid = args.id
    hub = _hub_url(args, cfg)

    try:
        req = urllib.request.Request(
            f"{hub}/submissions/{sid}/publish",
            data=b"{}",
            method="POST",
            headers={"Content-Type": "application/json", "Accept": "application/json"},
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
    version = data.get("version", "?")
    console.print(f"[green]✅ {name} v{version} publié sur le marketplace ![/]")
    console.print(f"   {hub}/plugins/{name}")


# ── dispatcher ────────────────────────────────────────────────


async def handle_hub(args) -> None:
    sub = getattr(args, "subcommand", None)
    dispatch = {
        "sign":    _hub_sign,
        "submit":  _hub_submit,
        "status":  _hub_status,
        "publish": _hub_publish,
    }
    handler = dispatch.get(sub)
    if handler:
        await handler(args)
    else:
        console.print("Usage : xcore hub <sign|submit|status|publish>")
