from __future__ import annotations

import typer
from rich.console import Console
from rich.markup import escape

from v2rm.cli.exposure import print_exposure_warnings
from v2rm.engines import resolve_engine
from v2rm.engines.aether import files as aether_files
from v2rm.errors import V2rmError
from v2rm.models.aether import AetherMode
from v2rm.models.enums import RoutePreset
from v2rm.net.addresses import ensure_listen_address_available
from v2rm.process import stack, supervisor
from v2rm.routing.model import RoutePlan
from v2rm.routing.presets import get_builtin
from v2rm.store import paths
from v2rm.store.auth import AuthStore
from v2rm.store.profiles import ProfileStore
from v2rm.store.state import AppStateStore

console = Console()

RAW_ROUTING_NOTE = (
    "Routing: this raw config uses its own routing rules; v2rm's route presets are not applied to raw configs."
)

AETHER_WAIT_NOTE = (
    "Aether is looking for a working Cloudflare gateway and proving the tunnel carries data before it opens "
    "the proxy. On a filtered network that can take a minute or two (Ctrl+C cancels)."
)


def _progress(line: str) -> None:
    console.print(f"  [dim]{escape(line)}[/dim]")


def connect_command(
    profile_ref: str | None = typer.Argument(
        None, help="Profile id or name to connect. Omit to reconnect using the active profile."
    ),
) -> None:
    """Connect: (re)generate the engine config and start the local SOCKS/HTTP proxy."""
    state_store = AppStateStore()
    state = state_store.load()
    profile_store = ProfileStore()

    if profile_ref:
        profile = profile_store.resolve(profile_ref)
    elif state.active_profile_id:
        profile = profile_store.resolve(state.active_profile_id)
    else:
        raise V2rmError(
            "No active profile. Run `v2rm connect <profile>` or `v2rm profile use <profile>` first."
        )

    # Raw/MASQUE profiles run on Xray and Hysteria2/TUIC on sing-box whatever the
    # default engine is -- with a note rather than a failure. The saved default
    # (`v2rm core use`) is never changed by connecting.
    engine, engine_note = resolve_engine(profile, state.active_engine)
    route_plan = _resolve_route_plan(state.route_preset)
    auth = AuthStore().load()

    ensure_listen_address_available(state.listen_address)

    if stack.uses_stack(profile):
        notes = _connect_stack(profile_store, profile, state, route_plan, auth)
        via = "chain" if profile.is_chain else engine.value
    else:
        notes = supervisor.connect(
            profile,
            engine,
            route_plan,
            state.socks_port,
            state.http_port,
            listen_address=state.listen_address,
            auth=auth,
        )
        via = engine.value
    state.active_profile_id = profile.id
    state_store.save(state)

    login = ", login required" if auth else ""
    console.print(
        f"[green]Connected[/green] via {via} -> {escape(profile.name)} "
        f"[dim](socks {state.listen_address}:{state.socks_port}, http {state.listen_address}:{state.http_port}{login})[/dim]"
    )
    if profile.is_chain:
        console.print(f"  [dim]chain: {escape(_chain_text(supervisor.status(), profile))}[/dim]")
    if engine_note:
        console.print(f"[dim]{escape(engine_note)}[/dim]")
    for note in notes:
        console.print(f"[yellow]Note:[/yellow] {escape(note)}")
    if profile.is_raw:
        console.print(f"[dim]{escape(RAW_ROUTING_NOTE)}[/dim]")
    print_exposure_warnings(console, state.listen_address, auth is not None, state.socks_port, state.http_port)


def _connect_stack(profile_store, profile, state, route_plan: RoutePlan, auth) -> list[str]:
    """Aether profiles and chains: one program per hop, so say what is going on while the
    tunnel is being found."""
    aether_ids = stack.aether_profile_ids(profile, profile_store)
    if aether_ids:
        for profile_id in aether_ids:
            member = profile_store.get(profile_id)
            note = stack.registration_note(member) if member else None
            if note:
                console.print(f"[yellow]Note:[/yellow] {escape(note)}")
        console.print(f"[dim]{AETHER_WAIT_NOTE}[/dim]")
    try:
        notes = supervisor.connect_stack(
            profile,
            state.active_engine,
            route_plan,
            state.socks_port,
            state.http_port,
            listen_address=state.listen_address,
            auth=auth,
            progress=_progress,
            store=profile_store,
        )
    except KeyboardInterrupt:
        console.print("[yellow]Cancelled; nothing was left running.[/yellow]")
        raise typer.Exit(code=130) from None
    # The first-connection notice was shown before the wait; don't repeat it afterwards.
    return [n for n in notes if not n.startswith(stack.FIRST_CONNECTION)]


def _chain_text(info: dict, profile) -> str:
    hops = info.get("hops")
    if isinstance(hops, list) and hops:
        return " -> ".join(str(h) for h in hops)
    return profile.server_display


def disconnect_command() -> None:
    """Disconnect the local SOCKS/HTTP proxy."""
    supervisor.disconnect()
    console.print("[green]Disconnected.[/green]")


def status_command() -> None:
    """Show the current connection status."""
    info = supervisor.status()
    if not info.get("connected"):
        console.print("[yellow]Not connected.[/yellow]")
        return

    listen = info.get("listen_address", "127.0.0.1")
    authenticated = bool(info.get("authenticated"))
    kind = info.get("profile_kind")
    starting = info.get("state") == "starting"
    console.print("[bold yellow]Starting...[/bold yellow]" if starting else "[bold green]Connected[/bold green]")
    console.print(f"  profile   {escape(str(info.get('profile_name', '?')))}" + (f" [dim]({kind})[/dim]" if kind else ""))
    console.print(f"  engine    {info.get('engine', '?')}")
    console.print(f"  pid       {info.get('pid')}")
    console.print(f"  socks     {listen}:{info.get('socks_port')}")
    console.print(f"  http      {listen}:{info.get('http_port')}")
    console.print(f"  login     {'required' if authenticated else 'none'}")
    if kind == "raw":
        console.print("  routing   the config's own rules [dim](route presets are not applied to raw configs)[/dim]")
    else:
        console.print(f"  routing   {AppStateStore().load().route_preset.value}")
    _print_stack(info)
    if info.get("listening") is False and not starting:
        console.print(
            f"  [red]The engine is running but nothing is accepting connections on {listen}:{info.get('socks_port')}.[/red] "
            f"[dim]Its log: {paths.engine_log_file()}[/dim]"
        )
    if info.get("socks_port") and info.get("http_port"):
        print_exposure_warnings(
            console, listen, authenticated, int(info["socks_port"]), int(info["http_port"]), full=False
        )


def _print_stack(info: dict) -> None:
    """The programs behind a connection made of several (an Aether profile, a chain), and what
    Aether remembers for quick reconnects."""
    members = info.get("stack")
    if not members:
        return
    hops = info.get("hops")
    if isinstance(hops, list) and len(hops) > 1:
        console.print(f"  chain     {escape(' -> '.join(str(h) for h in hops))}")
    for number, member in enumerate(members, start=1):
        mark = "[green]ok[/green]" if member.get("alive") else "[red]stopped[/red]"
        facing = "  [dim]serves your ports[/dim]" if member.get("user_facing") else ""
        console.print(
            f"    {number}. {escape(str(member.get('label', '?')))}  [dim]pid {member.get('pid')}, "
            f"{member.get('listen', '127.0.0.1')}:{member.get('socks_port')}[/dim]  {mark}{facing}"
        )
    for member in members:
        if not member.get("alive"):
            console.print(
                f"  [red]{escape(str(member.get('label', '?')))} has stopped, so traffic through this connection fails.[/red] "
                f"[dim]Its log: {escape(str(member.get('log', '?')))}. `v2rm connect` starts everything again.[/dim]"
            )
    if info.get("state") == "starting":
        console.print("  [dim]still starting: the last program is not ready yet[/dim]")
    _print_remembered_gateway(info)


def _print_remembered_gateway(info: dict) -> None:
    from v2rm.store.profiles import ProfileStore

    for profile_id in info.get("aether_ids") or []:
        profile = ProfileStore().get(profile_id)
        if profile is None or profile.aether is None:
            continue
        cache = aether_files.read_last_gateways(
            aether_files.lastconn_file(aether_files.config_path(profile.id), profile.aether.mode)
        )
        if cache is not None and cache.peer:
            console.print(
                f"  gateway   {escape(cache.peer)} [dim]({escape(profile.name)}: remembered for quick reconnect)[/dim]"
            )
        elif profile.aether.mode in (AetherMode.GOOL_CLASSIC, AetherMode.MIM):
            console.print(f"  [dim]gateway   {escape(profile.name)}: {profile.aether.mode.value} scans again after a restart[/dim]")


def _resolve_route_plan(preset: RoutePreset) -> RoutePlan:
    if preset == RoutePreset.CUSTOM:
        from v2rm.routing.custom import load_custom_route_plan

        return load_custom_route_plan()
    return get_builtin(preset)
