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

_TYPE_CHOICES = "vless, vmess, trojan, shadowsocks, hysteria2, tuic, masque, raw, aether, chain"


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


def _show_aether(p: Profile) -> None:
    from v2rm.engines.aether import files as aether_files
    from v2rm.models.aether import MASQUE_MODES
    from v2rm.net.proxy_url import redact

    s = p.aether
    assert s is not None
    _line("type", f"aether -- {s.label}")
    if s.mode in MASQUE_MODES:
        carrier = {"h3": "HTTP/3 (QUIC, UDP)", "h2": "HTTP/2 (TCP)"}.get(s.transport, "HTTP/3 (QUIC, UDP) -- Aether's default")
        _line("carrier", carrier)
    _line("gateway", s.outer or "found by scanning")
    if s.inner or s.mode.value in ("gool", "gool-classic", "mim"):
        _line("inner hop", s.inner or "found by scanning")
    _line("h2 peer", s.h2_peer)
    _line("scan", s.scan or "balanced (default)")
    _line("ip", s.ip or "v4 (default)")
    _line("noize", s.noize or "Aether's default for the mode")
    if s.fragment:
        _line("fragment", f"on (size {s.fragment_size or '8-16'} B, delay {s.fragment_delay or '2-10'} ms)")
    _line("sni", s.sni)
    _line("ech", "auto" if s.ech.lower() == "auto" else ("a config" if s.ech else ""))
    _line("tls", ", ".join(x for x in (f"ciphers {s.tls_ciphers}" if s.tls_ciphers else "", f"groups {s.tls_groups}" if s.tls_groups else "", "no GREASE" if s.disable_grease else "") if x))
    _line("upstream", redact(s.upstream))
    if s.route_block or s.route_direct:
        _line("routing", f"{len(s.route_block)} block, {len(s.route_direct)} direct rule(s); name sniffing {'on' if s.route_sniff else 'off'}")
        for rule in s.route_block:
            _line("  block", rule)
        for rule in s.route_direct:
            _line("  direct", rule)
    _line("exit only", s.exit_loc)
    _line("waits", f"{s.wait_secs} s for the proxy to come up" if s.wait_secs else "")
    _line("reconnect", f"quick reconnect {'on' if s.quick_reconnect else 'off'}" + (f", {s.reconnect_secs} s between attempts" if s.reconnect_secs else ""))
    if s.env:
        _line("extra env", ", ".join(sorted(s.env)))  # names only: values can be secrets
    base = aether_files.config_path(p.id)
    registered, needed = aether_files.identity_state(base, s.mode)
    _line("identity", f"{registered}/{needed} registered" + ("" if registered == needed else " (the first connection registers the rest)"))


def _show_chain(p: Profile) -> None:
    from v2rm.store.profiles import ProfileStore

    store = ProfileStore()
    _line("type", "chain -- each hop leaves through the one before it")
    hops = p.chain or []
    for number, hop in enumerate(hops, start=1):
        if hop.is_proxy:
            _line(f"hop {number}", f"{hop.label()} (a proxy already running)")
            continue
        member = store.get(hop.ref)
        if member is None:
            _line(f"hop {number}", f"{hop.label()}  [missing: it no longer exists]")
        else:
            _line(f"hop {number}", f"{member.name} ({member.type_label}, {member.server_display})")
    _line("traffic", "you -> " + " -> ".join(h.label() for h in hops) + " -> the internet")


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
        if p.is_aether:
            from v2rm.parsers.aether import link_omissions

            for item in link_omissions(p):
                typer.echo(f"Note: left out of the link: {item}", err=True)
        return

    if as_json:
        data = p.raw_config if p.is_raw else p.to_dict()
        typer.echo(json.dumps(data, indent=2, ensure_ascii=False))
        return

    console.print(f"[bold]{escape(p.name)}[/bold] [dim]({p.id})[/dim]")
    if p.is_raw:
        _show_raw(p)
    elif p.is_aether:
        _show_aether(p)
    elif p.is_chain:
        _show_chain(p)
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

    if (p.is_aether or p.is_chain) and set(given) - {"name"}:
        kind = "an Aether profile" if p.is_aether else "a chain"
        raise V2rmError(
            f"{p.name} is {kind}: it has no server, port or credentials of its own to set. Run "
            f"`v2rm profile edit {ref}` with no flags to edit its settings (only --name can be given)."
        )

    if p.is_raw and set(given) - {"name"}:
        raise V2rmError(
            "A raw Xray profile is a complete config with no server, port or credentials of its own to set: "
            f"run `v2rm profile edit {ref}` with no flags to edit its JSON (only --name can be given)."
        )

    if not given:
        p = _edit_raw_in_editor(p) if p.is_raw else _edit_in_editor(p)
        _validate_edited(p)
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


def _validate_edited(profile: Profile) -> None:
    """A hand edit of an Aether profile or a chain must still be one Aether and v2rm can run:
    the same checks as when it was made, so a typo is caught now, not at connect time."""
    from v2rm.errors import ProfileValidationError

    try:
        if profile.is_aether:
            from v2rm.parsers.aether import validate_aether

            validate_aether(profile)
        elif profile.is_chain:
            from v2rm.process import stack

            store = ProfileStore()
            stack.check_composition(stack.resolve_hops(profile, store), profile.name)
    except ProfileValidationError as exc:
        raise V2rmError(f"Not saved: {exc}") from exc


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

    from v2rm.cli.chain import chains_using

    users = chains_using(p.id, store)
    if users and not force:
        names = ", ".join(f"'{c.name}'" for c in users)
        raise V2rmError(
            f"'{p.name}' is a hop of the chain(s) {names}, which would stop working. "
            "Remove those first, or pass --force."
        )

    prompt = f"Remove profile '{p.name}' ({p.id})?"
    if p.is_aether:
        prompt = f"Remove profile '{p.name}' ({p.id}) and delete its WARP identity (its private keys)?"
    if not yes and not typer.confirm(prompt):
        raise typer.Exit()

    store.remove(p.id)
    console.print(f"[green]Removed[/green] {escape(p.name)}")
    if p.is_aether:
        from v2rm.engines.aether.files import remove_profile_state

        if remove_profile_state(p.id):
            console.print("  [dim]Its WARP identity and remembered gateways were deleted too.[/dim]")
    if users:
        console.print(f"  [yellow]Chains still pointing at it (now broken): {', '.join(escape(c.name) for c in users)}[/yellow]")


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
