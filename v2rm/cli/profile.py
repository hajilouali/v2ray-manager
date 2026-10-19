from __future__ import annotations

import json
import os
import shlex
import subprocess
import tempfile
from pathlib import Path

import typer
import yaml
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from v2rm.engines.versioning import raw_version_requirement
from v2rm.engines.xray.raw import profile_is_serverless
from v2rm.errors import ParseError, V2rmError
from v2rm.models.enums import Protocol
from v2rm.models.profile import Profile
from v2rm.parsers.masque import validate_masque
from v2rm.parsers.raw import parse_json_text, validate_raw_config
from v2rm.store.profiles import ProfileStore
from v2rm.store.state import AppStateStore

console = Console()
profile_app = typer.Typer(help="Manage saved configs (profiles).")

_TYPE_CHOICES = "vless, vmess, trojan, shadowsocks, hysteria2, tuic, masque, raw"


def _matches_type(profile: Profile, wanted: str) -> bool:
    wanted = wanted.strip().lower()
    return wanted in (profile.protocol.value, profile.type_label)


def _editor_command(editor: str) -> list[str]:
    parts = shlex.split(editor, posix=os.name != "nt")
    return parts or ["nano"]


@profile_app.command("list")
def list_profiles(
    subscription: str | None = typer.Option(
        None, "--subscription", help="Only show profiles from this subscription (id/name)."
    ),
    protocol: str | None = typer.Option(
        None, "--protocol", help=f"Only show profiles of this type ({_TYPE_CHOICES})."
    ),
) -> None:
    """List saved profiles."""
    store = ProfileStore()
    profiles = store.list()

    if subscription:
        from v2rm.store.subscriptions import SubscriptionStore

        sub = SubscriptionStore().resolve(subscription)
        profiles = [p for p in profiles if p.subscription_id == sub.id]
    if protocol:
        profiles = [p for p in profiles if _matches_type(p, protocol)]

    active_id = AppStateStore().load().active_profile_id

    table = Table(show_lines=False)
    table.add_column("")
    table.add_column("ID")
    table.add_column("Name")
    table.add_column("Type")
    table.add_column("Server")
    table.add_column("Source")

    for p in profiles:
        marker = "[bold green]*[/bold green]" if p.id == active_id else ""
        table.add_row(marker, p.id, escape(p.name), p.type_label, escape(p.server_display), p.source.value)

    console.print(table)
    if not profiles:
        console.print("[dim]No profiles yet. Add one with `v2rm add <link>`.[/dim]")


def _line(label: str, value: object) -> None:
    if value not in (None, "", [], {}):
        console.print(f"  {label:<10} {escape(str(value))}")


def _shorten(text: str, limit: int = 32) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _show_raw(p: Profile) -> None:
    config = p.raw_config or {}
    outbounds = [o for o in config.get("outbounds") or [] if isinstance(o, dict)]
    inbounds = [i for i in config.get("inbounds") or [] if isinstance(i, dict)]
    rules = (config.get("routing") or {}).get("rules") or []
    minimum, maximum = raw_version_requirement(p)

    _line("type", "raw -- a complete Xray config, run as written (only its inbounds are replaced)")
    _line("server", p.server_display)
    tags = [f"{o.get('tag', '?')} ({o.get('protocol', '?')})" for o in outbounds]
    _line("outbounds", f"{len(outbounds)}: " + ", ".join(tags[:8]) + (", ..." if len(tags) > 8 else ""))
    _line("inbounds", f"{len(inbounds)} ({', '.join(str(i.get('protocol', '?')) for i in inbounds)}) -- replaced by v2rm's own SOCKS/HTTP")
    _line("routing", f"{len(rules)} rule(s) of its own; route presets are not applied")
    if minimum or maximum:
        _line("needs", "Xray-core " + " and ".join(x for x in (f">= {minimum}" if minimum else "", f"<= {maximum}" if maximum else "") if x))
    if profile_is_serverless(p):
        _line("note", "no remote server: a direct connection that evades DPI, not a tunnel")


def _show_link_based(p: Profile) -> None:
    _line("type", p.type_label)
    _line("server", p.server_display)
    _line("uuid", p.uuid)
    if p.password:
        _line("password", "*" * min(len(p.password), 12))
    _line("user", p.extra.get("user"))
    _line("method", p.method)
    _line("flow", p.flow)
    _line("encryption", _shorten(p.encryption))
    _line("packet-enc", p.packet_encoding)
    _line("congestion", p.congestion_control)
    _line("network", p.transport.network.value)
    _line("path", p.transport.path)
    _line("host", p.transport.host)
    _line("service", p.transport.service_name)
    _line("mode", p.transport.mode)
    _line("headers", ", ".join(p.transport.headers))  # names only: values can be tokens
    _line("xhttp", "extra settings" if p.transport.xhttp_extra else "")
    if p.transport.finalmask:
        kinds = [str(m.get("type", "?")) for masks in p.transport.finalmask.values() if isinstance(masks, list) for m in masks if isinstance(m, dict)]
        _line("finalmask", ", ".join(kinds) or "yes")
    _line("security", p.tls.security.value)
    _line("sni", p.tls.sni)
    _line("alpn", ",".join(p.tls.alpn))
    _line("fingerprint", p.tls.fingerprint)
    _line("ciphers", _shorten(p.tls.cipher_suites, 48))
    _line("ech", _shorten(p.tls.ech_config_list, 48))
    if p.tls.reality:
        _line("reality", f"pbk={p.tls.reality.public_key} sid={p.tls.reality.short_id}")


@profile_app.command("show")
def show_profile(
    ref: str = typer.Argument(..., help="Profile id or name."),
    link: bool = typer.Option(False, "--link", help="Print the profile re-encoded as a share link."),
    as_json: bool = typer.Option(
        False,
        "--json",
        help="Print the stored data as JSON. For a raw Xray profile that is the config itself "
        "(usable again with `v2rm add --json -`).",
    ),
) -> None:
    """Show full detail for a profile."""
    store = ProfileStore()
    p = store.resolve(ref)

    if link and as_json:
        raise V2rmError("Use either --link or --json, not both.")

    if link:
        from v2rm.parsers import to_link

        # A raw profile has no link: to_link says so and points at --json.
        typer.echo(to_link(p))
        return

    if as_json:
        data = p.raw_config if p.is_raw else p.to_dict()
        typer.echo(json.dumps(data, indent=2, ensure_ascii=False))
        return

    console.print(f"[bold]{escape(p.name)}[/bold] [dim]({p.id})[/dim]")
    if p.is_raw:
        _show_raw(p)
    else:
        _show_link_based(p)
    console.print(f"  source     {p.source.value}")
    console.print(f"  created    {p.created_at}")


@profile_app.command("edit")
def edit_profile(
    ref: str = typer.Argument(..., help="Profile id or name."),
    name: str | None = typer.Option(None, help="New display name."),
    server: str | None = typer.Option(None, help="New server host/IP."),
    port: int | None = typer.Option(None, help="New server port."),
    uuid: str | None = typer.Option(None, help="New uuid (vmess/vless/tuic)."),
    password: str | None = typer.Option(None, help="New password (trojan/shadowsocks/hysteria2/tuic/masque)."),
    method: str | None = typer.Option(None, help="New cipher/encryption method (shadowsocks/vmess)."),
    flow: str | None = typer.Option(None, help="New flow (vless)."),
    congestion_control: str | None = typer.Option(None, help="New congestion control (tuic)."),
    sni: str | None = typer.Option(None, help="New TLS SNI."),
) -> None:
    """Edit a profile's fields. With no flags, opens $EDITOR: on the JSON config for a raw Xray
    profile (checked for valid JSON with an `outbounds` list), otherwise on a YAML dump."""
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

    if p.is_raw and set(given) - {"name"}:
        raise V2rmError(
            "A raw Xray profile is a complete config with no server, port or credentials of its own to set: "
            f"run `v2rm profile edit {ref}` with no flags to edit its JSON (only --name can be given)."
        )

    if not given:
        p = _edit_raw_in_editor(p) if p.is_raw else _edit_in_editor(p)
    else:
        for key, value in given.items():
            if key == "sni":
                p.tls.sni = value
            else:
                setattr(p, key, value)
        if p.protocol == Protocol.MASQUE:
            validate_masque(p)

    store.update(p)
    console.print(f"[green]Updated[/green] {escape(p.name)} [dim]({p.id})[/dim]")


def _edit_raw_in_editor(profile: Profile) -> Profile:
    """Open the JSON config in $EDITOR. A mistake (invalid JSON, no `outbounds`
    list) is reported and the editor reopened on what was typed, rather than
    throwing the edit away."""
    editor = _editor_command(os.environ.get("EDITOR", "nano"))
    text = json.dumps(profile.raw_config, indent=2, ensure_ascii=False) + "\n"

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as f:
        f.write(text)
        tmp_path = Path(f.name)

    try:
        while True:
            subprocess.run([*editor, str(tmp_path)], check=True)
            try:
                config = validate_raw_config(parse_json_text(tmp_path.read_text(encoding="utf-8")))
                break
            except ParseError as exc:
                console.print(f"[red]Not saved:[/red] {escape(str(exc))}")
                if not typer.confirm("Edit again?", default=True):
                    raise V2rmError("Edit abandoned; the profile is unchanged.") from exc
    finally:
        tmp_path.unlink(missing_ok=True)

    old_remarks = str((profile.raw_config or {}).get("remarks") or "").strip()
    new_remarks = str(config.get("remarks") or "").strip()
    profile.raw_config = config
    if new_remarks and new_remarks != old_remarks:
        profile.name = new_remarks  # the name follows `remarks`, as it did when the config was added
    return profile


def _edit_in_editor(profile: Profile) -> Profile:
    editor = _editor_command(os.environ.get("EDITOR", "nano"))
    text = yaml.safe_dump(profile.to_dict(), sort_keys=False, allow_unicode=True)

    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False, encoding="utf-8") as f:
        f.write(text)
        tmp_path = Path(f.name)

    try:
        subprocess.run([*editor, str(tmp_path)], check=True)
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
    console.print(f"[green]Removed[/green] {escape(p.name)}")


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
    console.print(f"[green]Renamed[/green] to {escape(new_name)}")


@profile_app.command("use")
def use_profile(ref: str = typer.Argument(..., help="Profile id or name.")) -> None:
    """Set the active profile (live-switches if already connected)."""
    store = ProfileStore()
    p = store.resolve(ref)

    state_store = AppStateStore()
    state = state_store.load()
    state.active_profile_id = p.id
    state_store.save(state)
    console.print(f"[green]Active profile set to[/green] {escape(p.name)} [dim]({p.id})[/dim]")

    from v2rm.process import supervisor

    connected, _ = supervisor.is_connected()
    if connected:
        from v2rm.cli.connect import connect_command

        connect_command(None)
