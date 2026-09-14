from __future__ import annotations

import os
import subprocess
import tempfile
from pathlib import Path

import typer
import yaml
from rich.console import Console
from rich.table import Table

from v2rm.errors import V2rmError
from v2rm.models.enums import Protocol
from v2rm.models.profile import Profile
from v2rm.store.profiles import ProfileStore
from v2rm.store.state import AppStateStore

console = Console()
profile_app = typer.Typer(help="Manage saved configs (profiles).")


@profile_app.command("list")
def list_profiles(
    subscription: str | None = typer.Option(
        None, "--subscription", help="Only show profiles from this subscription (id/name)."
    ),
    protocol: Protocol | None = typer.Option(None, "--protocol", help="Only show profiles of this protocol."),
) -> None:
    """List saved profiles."""
    store = ProfileStore()
    profiles = store.list()

    if subscription:
        from v2rm.store.subscriptions import SubscriptionStore

        sub = SubscriptionStore().resolve(subscription)
        profiles = [p for p in profiles if p.subscription_id == sub.id]
    if protocol:
        profiles = [p for p in profiles if p.protocol == protocol]

    active_id = AppStateStore().load().active_profile_id

    table = Table(show_lines=False)
    table.add_column("")
    table.add_column("ID")
    table.add_column("Name")
    table.add_column("Protocol")
    table.add_column("Server")
    table.add_column("Source")

    for p in profiles:
        marker = "[bold green]*[/bold green]" if p.id == active_id else ""
        table.add_row(marker, p.id, p.name, p.protocol.value, p.server_display, p.source.value)

    console.print(table)
    if not profiles:
        console.print("[dim]No profiles yet. Add one with `v2rm add <link>`.[/dim]")


@profile_app.command("show")
def show_profile(
    ref: str = typer.Argument(..., help="Profile id or name."),
    link: bool = typer.Option(False, "--link", help="Print the profile re-encoded as a share link."),
) -> None:
    """Show full detail for a profile."""
    store = ProfileStore()
    p = store.resolve(ref)

    if link:
        from v2rm.parsers import to_link

        console.print(to_link(p))
        return

    console.print(f"[bold]{p.name}[/bold] [dim]({p.id})[/dim]")
    console.print(f"  protocol   {p.protocol.value}")
    console.print(f"  server     {p.server_display}")
    if p.uuid:
        console.print(f"  uuid       {p.uuid}")
    if p.password:
        console.print(f"  password   {'*' * min(len(p.password), 12)}")
    if p.method:
        console.print(f"  method     {p.method}")
    if p.flow:
        console.print(f"  flow       {p.flow}")
    if p.congestion_control:
        console.print(f"  congestion {p.congestion_control}")
    console.print(f"  network    {p.transport.network.value}")
    if p.transport.path:
        console.print(f"  path       {p.transport.path}")
    if p.transport.host:
        console.print(f"  host       {p.transport.host}")
    if p.transport.service_name:
        console.print(f"  service    {p.transport.service_name}")
    console.print(f"  security   {p.tls.security.value}")
    if p.tls.sni:
        console.print(f"  sni        {p.tls.sni}")
    if p.tls.alpn:
        console.print(f"  alpn       {','.join(p.tls.alpn)}")
    if p.tls.reality:
        console.print(f"  reality    pbk={p.tls.reality.public_key} sid={p.tls.reality.short_id}")
    console.print(f"  source     {p.source.value}")
    console.print(f"  created    {p.created_at}")


@profile_app.command("edit")
def edit_profile(
    ref: str = typer.Argument(..., help="Profile id or name."),
    name: str | None = typer.Option(None, help="New display name."),
    server: str | None = typer.Option(None, help="New server host/IP."),
    port: int | None = typer.Option(None, help="New server port."),
    uuid: str | None = typer.Option(None, help="New uuid (vmess/vless/tuic)."),
    password: str | None = typer.Option(None, help="New password (trojan/shadowsocks/hysteria2/tuic)."),
    method: str | None = typer.Option(None, help="New cipher/encryption method (shadowsocks/vmess)."),
    flow: str | None = typer.Option(None, help="New flow (vless)."),
    congestion_control: str | None = typer.Option(None, help="New congestion control (tuic)."),
    sni: str | None = typer.Option(None, help="New TLS SNI."),
) -> None:
    """Edit a profile's fields. With no flags, opens $EDITOR on a YAML dump instead."""
    store = ProfileStore()
    p = store.resolve(ref)

    given = {
        "name": name,
        "server": server,
        "port": port,
        "uuid": uuid,
        "password": password,
        "method": method,
        "flow": flow,
        "congestion_control": congestion_control,
        "sni": sni,
    }
    given = {k: v for k, v in given.items() if v is not None}

    if not given:
        p = _edit_in_editor(p)
    else:
        for key, value in given.items():
            if key == "sni":
                p.tls.sni = value
            else:
                setattr(p, key, value)

    store.update(p)
    console.print(f"[green]Updated[/green] {p.name} [dim]({p.id})[/dim]")


def _edit_in_editor(profile: Profile) -> Profile:
    editor = os.environ.get("EDITOR", "nano")
    text = yaml.safe_dump(profile.to_dict(), sort_keys=False, allow_unicode=True)

    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False, encoding="utf-8") as f:
        f.write(text)
        tmp_path = Path(f.name)

    try:
        subprocess.run([editor, str(tmp_path)], check=True)
        edited_text = tmp_path.read_text(encoding="utf-8")
        data = yaml.safe_load(edited_text)
        if not data:
            raise V2rmError("Empty profile file; aborting edit")
        try:
            return Profile.from_dict(data)
        except (KeyError, ValueError, TypeError) as exc:
            raise V2rmError(f"Invalid profile data after edit: {exc}") from exc
    finally:
        tmp_path.unlink(missing_ok=True)


@profile_app.command("remove")
def remove_profile(
    ref: str = typer.Argument(..., help="Profile id or name."),
    yes: bool = typer.Option(False, "--yes", "-y", help="Don't ask for confirmation."),
    force: bool = typer.Option(False, "--force", help="Remove even if it's the currently connected profile."),
) -> None:
    """Remove a profile."""
    store = ProfileStore()
    p = store.resolve(ref)

    state = AppStateStore().load()
    if state.active_profile_id == p.id and not force:
        raise V2rmError(
            f"'{p.name}' is the currently active profile. Disconnect first, or pass --force."
        )

    if not yes and not typer.confirm(f"Remove profile '{p.name}' ({p.id})?"):
        raise typer.Exit()

    store.remove(p.id)
    console.print(f"[green]Removed[/green] {p.name}")


@profile_app.command("rename")
def rename_profile(
    ref: str = typer.Argument(..., help="Profile id or name."),
    new_name: str = typer.Argument(..., help="New display name."),
) -> None:
    """Rename a profile."""
    store = ProfileStore()
    p = store.resolve(ref)
    p.name = new_name
    store.update(p)
    console.print(f"[green]Renamed[/green] to {new_name}")


@profile_app.command("use")
def use_profile(ref: str = typer.Argument(..., help="Profile id or name.")) -> None:
    """Set the active profile (live-switches if already connected)."""
    store = ProfileStore()
    p = store.resolve(ref)

    state_store = AppStateStore()
    state = state_store.load()
    state.active_profile_id = p.id
    state_store.save(state)
    console.print(f"[green]Active profile set to[/green] {p.name} [dim]({p.id})[/dim]")

    from v2rm.process import supervisor

    connected, _ = supervisor.is_connected()
    if connected:
        from v2rm.cli.connect import connect_command

        connect_command(None)
