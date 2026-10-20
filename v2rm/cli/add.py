from __future__ import annotations

import sys
from pathlib import Path

import typer
from rich.console import Console
from rich.markup import escape

from v2rm.cli.add_aether import add_aether_command
from v2rm.cli.groups import DefaultCommandGroup
from v2rm.errors import V2rmError
from v2rm.models.profile import Profile
from v2rm.parsers import parse_links
from v2rm.parsers.masque import build_profile
from v2rm.parsers.raw import is_xray_json_body, parse_xray_json
from v2rm.store.profiles import ProfileStore

console = Console()

add_app = typer.Typer(
    cls=DefaultCommandGroup,
    help="Add configs: `v2rm add <link>` (also `-` for stdin, `-f FILE`, `--json FILE`), `v2rm add masque ...` or `v2rm add aether ...`.",
    context_settings={"ignore_unknown_options": True},
    no_args_is_help=False,
)


# ---- shared helpers (plain functions: the menu calls these too) ---------------------------------------


def read_source(source: str) -> str:
    """Text from a file path, or from stdin for '-'."""
    if source == "-":
        return sys.stdin.read()
    path = Path(source)
    if not path.is_file():
        raise V2rmError(f"File not found: {source}")
    return path.read_text(encoding="utf-8")


def _report(profiles: list[Profile], errors: list[tuple[str, str]]) -> None:
    for p in profiles:
        console.print(
            f"[green]+[/green] {escape(p.name)} [dim]({p.type_label}, {escape(p.server_display)}, id {p.id})[/dim]"
        )
    for label, message in errors:
        shown = label if len(label) <= 60 else label[:57] + "..."
        console.print(f"[red]x[/red] {escape(shown)} [dim]-> {escape(message)}[/dim]")


def add_links_text(text: str) -> bool:
    """Parse share links (or, if it is really an Xray JSON config, that), store
    what parsed, print the outcome. Returns False if nothing could be added."""
    if is_xray_json_body(text):
        console.print("[dim]This is an Xray JSON config -- adding it as one (same as --json).[/dim]")
        return add_json_text(text)

    profiles, errors = parse_links(text)
    if profiles:
        ProfileStore().add_many(profiles)
    _report(profiles, errors)
    if not profiles and not errors:
        console.print("[yellow]No links found.[/yellow]")
    return bool(profiles)


def add_json_text(text: str) -> bool:
    """Add Xray JSON config(s): one object, or an array of them. Returns False
    if none could be added."""
    profiles, errors = parse_xray_json(text)
    if profiles:
        ProfileStore().add_many(profiles)
    _report(profiles, errors)
    return bool(profiles)


def add_masque_profile(
    server: str,
    port: int,
    sni: str,
    alpn: str,
    user: str | None,
    password: str | None,
    path: str,
    host: str,
    headers: list[str],
    fingerprint: str,
    name: str | None,
) -> Profile:
    """Validate and store a MASQUE profile from individual fields."""
    if bool(user) != bool(password):
        raise V2rmError("--user and --pass go together: give both, or neither.")

    header_map: dict[str, str] = {}
    for entry in headers:
        key, colon, value = entry.partition(":")
        if not colon or not key.strip():
            raise V2rmError(f"--header must look like 'Name: value', got {entry!r}")
        header_map[key.strip()] = value.strip()

    profile = build_profile(
        server=server.strip(),
        port=port,
        sni=sni.strip(),
        alpn=[a.strip() for a in alpn.split(",") if a.strip()] or None,
        user=user or "",
        password=password or "",
        path=path,
        host=host,
        headers=header_map,
        fingerprint=fingerprint,
        name=(name or "").strip(),
    )
    (stored,) = ProfileStore().add_many([profile])
    _report([stored], [])
    return stored


# ---- commands -----------------------------------------------------------------------------------------


@add_app.command("link")
def add_command(
    link: str | None = typer.Argument(
        None,
        help="A share link (vmess://, vless://, trojan://, ss://, hysteria2://, tuic://, masque://). "
        "Use '-' to read one or more links (one per line) from stdin.",
    ),
    file: Path | None = typer.Option(
        None, "--file", "-f", help="Read newline-separated links from a file instead."
    ),
    json_source: str | None = typer.Option(
        None,
        "--json",
        metavar="FILE",
        help="Add a complete Xray JSON config (one object, or an array of them) from FILE, or '-' for stdin.",
    ),
) -> None:
    """Add one or more configs from share links or Xray JSON (the default `v2rm add` form)."""
    if json_source is not None:
        if link is not None or file is not None:
            raise V2rmError("--json can't be combined with a link or --file.")
        if not add_json_text(read_source(json_source)):
            raise typer.Exit(code=1)
        return

    if file is not None:
        text = file.read_text(encoding="utf-8")
    elif link == "-":
        text = sys.stdin.read()
    elif link:
        text = link
    else:
        console.print("[yellow]Provide a link, '-' to read stdin, --file PATH, --json FILE, or use `v2rm add masque`.[/yellow]")
        raise typer.Exit(code=1)

    if not add_links_text(text):
        raise typer.Exit(code=1)


@add_app.command("masque")
def add_masque_command(
    server: str = typer.Option(..., "--server", help="MASQUE proxy host name or IP address."),
    port: int = typer.Option(443, "--port", help="Server port."),
    sni: str = typer.Option(..., "--sni", help="TLS server name to present."),
    alpn: str = typer.Option(
        "h2",
        "--alpn",
        help="'h2' = HTTP/2 (default); 'h3' = HTTP/3 over QUIC. Comma-separate to offer several.",
    ),
    user: str | None = typer.Option(None, "--user", help="User name for the proxy (with --pass)."),
    password: str | None = typer.Option(None, "--pass", help="Password for the proxy (with --user)."),
    path: str = typer.Option("", "--path", help="Request path, starting with '/'."),
    host: str = typer.Option("", "--host", help="Host/authority to send, if different from the server."),
    header: list[str] = typer.Option([], "--header", help="Extra request header 'Name: value'. Repeatable."),
    fp: str = typer.Option("", "--fp", help="TLS fingerprint to imitate, e.g. chrome."),
    name: str | None = typer.Option(None, "--name", help="Display name (default host:port)."),
) -> None:
    """Add a MASQUE (HTTP/2 or HTTP/3 CONNECT) proxy. Runs on Xray-core."""
    add_masque_profile(server, port, sni, alpn, user, password, path, host, list(header), fp, name)


add_app.command("aether")(add_aether_command)
