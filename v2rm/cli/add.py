from __future__ import annotations

import sys
from pathlib import Path

import typer
from rich.console import Console

from v2rm.parsers import parse_links
from v2rm.store.profiles import ProfileStore

console = Console()


def add_command(
    link: str | None = typer.Argument(
        None,
        help="A share link (vmess://, vless://, trojan://, ss://, hysteria2://, tuic://). "
        "Use '-' to read one or more links (one per line) from stdin.",
    ),
    file: Path | None = typer.Option(
        None, "--file", "-f", help="Read newline-separated links from a file instead."
    ),
) -> None:
    """Add one or more configs from share link(s)."""
    if file is not None:
        text = file.read_text(encoding="utf-8")
    elif link == "-":
        text = sys.stdin.read()
    elif link:
        text = link
    else:
        console.print("[yellow]Provide a link, '-' to read stdin, or --file PATH.[/yellow]")
        raise typer.Exit(code=1)

    profiles, errors = parse_links(text)
    store = ProfileStore()
    if profiles:
        store.add_many(profiles)

    for p in profiles:
        console.print(f"[green]+[/green] {p.name} [dim]({p.protocol.value}, {p.server_display}, id {p.id})[/dim]")
    for line, message in errors:
        shown = line if len(line) <= 60 else line[:57] + "..."
        console.print(f"[red]x[/red] {shown} [dim]-> {message}[/dim]")

    if not profiles and not errors:
        console.print("[yellow]No links found.[/yellow]")
    if errors and not profiles:
        raise typer.Exit(code=1)
