from __future__ import annotations

import typer
from rich.console import Console
from rich.markup import escape
from rich.prompt import Confirm, IntPrompt, Prompt

from v2rm.cli.connect import connect_command, disconnect_command, status_command
from v2rm.cli.sub import update_subscription
from v2rm.cli.test import test_command
from v2rm.errors import V2rmError
from v2rm.models.profile import Profile
from v2rm.models.subscription import Subscription
from v2rm.process import supervisor
from v2rm.store.profiles import ProfileStore
from v2rm.store.subscriptions import SubscriptionStore

console = Console()

# Every _safe(fn, ...) call below invokes a Typer command function directly,
# bypassing Typer's own CLI parsing -- which is normally what resolves a
# `typer.Option(...)`/`typer.Argument(...)` default into a plain value.
# Called this way, any parameter left unspecified keeps that raw sentinel
# object instead of its real default, so every parameter of the target
# function must be passed explicitly here (positionally or by keyword).


def _safe(fn, *args, **kwargs) -> None:
    try:
        fn(*args, **kwargs)
    except V2rmError as exc:
        console.print(f"[bold red]Error:[/bold red] {escape(str(exc))}")
    except typer.Exit:
        pass


def _print_status_line() -> None:
    info = supervisor.status()
    if info.get("connected"):
        console.print(
            f"[bold green]Connected[/bold green] via {info.get('engine')} -> {escape(str(info.get('profile_name')))}"
        )
    else:
        console.print("[dim]Not connected[/dim]")


def _pick_profile(prompt: str) -> Profile | None:
    profiles = ProfileStore().list()
    if not profiles:
        console.print("[yellow]No profiles yet -- add one first.[/yellow]")
        return None

    for i, p in enumerate(profiles, start=1):
        console.print(f"  {i}) {escape(p.name)} [dim]({p.type_label}, {escape(p.server_display)})[/dim]")
    idx = IntPrompt.ask(prompt, default=0)
    if idx < 1 or idx > len(profiles):
        return None
    return profiles[idx - 1]


def _pick_subscription(prompt: str) -> Subscription | None:
    subs = SubscriptionStore().list()
    if not subs:
        console.print("[yellow]No subscriptions yet -- add one first.[/yellow]")
        return None

    for i, s in enumerate(subs, start=1):
        console.print(f"  {i}) {escape(s.name)} [dim]({escape(s.url)})[/dim]")
    idx = IntPrompt.ask(prompt, default=0)
    if idx < 1 or idx > len(subs):
        return None
    return subs[idx - 1]


def _connect_flow() -> None:
    profile = _pick_profile("Connect to profile #")
    if profile is not None:
        _safe(connect_command, profile.id)


def _add_link_flow() -> None:
    from v2rm.cli.add import add_links_text

    link = Prompt.ask("Paste a share link")
    if link:
        _safe(add_links_text, link)


def _add_json_flow() -> None:
    from v2rm.cli.add import add_json_text, read_source

    source = Prompt.ask("Path to an Xray JSON file (to paste JSON instead, use `v2rm add --json -`)").strip()
    if source:
        _safe(lambda: add_json_text(read_source(source)))


def _add_masque_flow() -> None:
    from v2rm.cli.add import add_masque_profile

    server = Prompt.ask("MASQUE server (host name or IP)").strip()
    if not server:
        return
    port = IntPrompt.ask("Port", default=443)
    sni = Prompt.ask("TLS server name (SNI)", default=server).strip()
    alpn = Prompt.ask("ALPN (h2 = HTTP/2, h3 = HTTP/3)", default="h2")
    user = Prompt.ask("User name (leave empty for none)", default="").strip()
    password = Prompt.ask("Password", password=True) if user else ""
    path = Prompt.ask("Path (leave empty for none)", default="").strip()
    name = Prompt.ask("Name (leave empty for host:port)", default="").strip()
    # A plain function, so every argument is explicit (no Typer defaults involved).
    _safe(add_masque_profile, server, port, sni, alpn, user or None, password or None, path, "", [], "", name or None)


def _add_aether_flow() -> None:
    from v2rm.cli.add_aether import add_aether_profile
    from v2rm.models.aether import MASQUE_MODES, TWO_HOP_MODES, AetherMode, AetherSettings

    modes = [m.value for m in AetherMode]
    console.print(
        "  masque = WARP over MASQUE | wg = classic WireGuard | gool = WireGuard inside MASQUE (foreign exit) | "
        "gool-classic = WireGuard in WireGuard | mim = MASQUE in MASQUE"
    )
    mode = AetherMode(Prompt.ask("Mode", choices=modes, default="masque"))
    transport = ""
    if mode in MASQUE_MODES:
        transport = Prompt.ask("Carrier (h3 = QUIC over UDP, h2 = HTTP/2 over TCP)", choices=["h3", "h2"], default="h3")
    fragment = False
    fragment_size = fragment_delay = ""
    if transport == "h2":
        fragment = Confirm.ask("Fragment the TLS ClientHello (for firewalls that reset the WARP server name)?", default=False)
        if fragment:
            fragment_size = Prompt.ask("  Fragment size in bytes (N or A-B, empty = 8-16)", default="").strip()
            fragment_delay = Prompt.ask("  Delay between fragments in ms (N or A-B, empty = 2-10)", default="").strip()
    noize = Prompt.ask("Obfuscation (off/light/firewall/balanced/gfw/aggressive, empty = Aether's default)", default="").strip()
    outer = inner = ""
    if Confirm.ask("Name the gateway yourself instead of scanning for one?", default=False):
        outer = Prompt.ask("  Gateway (ip:port; for gool-classic/mim the outer hop)").strip()
        if mode in TWO_HOP_MODES:
            inner = Prompt.ask("  Second hop (ip:port, empty = found by scanning)", default="").strip()
    upstream = Prompt.ask("Dial out through a proxy already running here? (e.g. socks5://127.0.0.1:1080, empty = no)", default="").strip()
    name = Prompt.ask("Name (empty = automatic)", default="").strip()
    settings = AetherSettings(
        mode=mode,
        transport=transport,
        fragment=fragment,
        fragment_size=fragment_size,
        fragment_delay=fragment_delay,
        noize=noize,
        outer=outer,
        inner=inner,
        upstream=upstream,
    )
    _safe(add_aether_profile, settings, name, None)


def _add_chain_flow() -> None:
    from v2rm.cli.chain import add_chain

    profiles = [p for p in ProfileStore().list() if not p.is_chain]
    if len(profiles) < 2:
        console.print("[yellow]A chain needs at least two saved profiles -- add some first.[/yellow]")
        return
    console.print("Hops are listed the way the traffic travels: the first is closest to you, the last is what the internet sees.")
    for i, p in enumerate(profiles, start=1):
        console.print(f"  {i}) {escape(p.name)} [dim]({p.type_label}, {escape(p.server_display)})[/dim]")
    answer = Prompt.ask("Hops, as numbers separated by spaces (a proxy address like socks5://127.0.0.1:1080 may come first)")
    refs: list[str] = []
    for token in answer.split():
        if token.isdigit() and 1 <= int(token) <= len(profiles):
            refs.append(profiles[int(token) - 1].id)
        elif "://" in token:
            refs.append(token)
        else:
            console.print(f"[yellow]'{escape(token)}' is not one of the numbers above.[/yellow]")
            return
    name = Prompt.ask("Name for the chain").strip()
    _safe(add_chain, name, refs)


def _proxy_settings_flow() -> None:
    from v2rm.cli.port import apply_settings, show_ports
    from v2rm.store.state import AppStateStore

    _safe(show_ports)
    console.print(
        "Login for the SOCKS and HTTP ports: keep = leave it as it is | "
        "set = require a user name and password | none = no user name or password"
    )
    login = Prompt.ask("Login", choices=["keep", "set", "none"], default="keep")
    user = None
    if login == "set":
        user = Prompt.ask("  User name (the password is asked for at the end)").strip()
        if not user:
            console.print("[yellow]A user name is needed -- nothing changed.[/yellow]")
            return

    state = AppStateStore().load()
    new_socks = IntPrompt.ask("SOCKS port", default=state.socks_port)
    new_http = IntPrompt.ask("HTTP port", default=state.http_port)
    console.print("Listen address: 127.0.0.1 = this machine only | 0.0.0.0 = every interface | docker = the Docker bridge")
    new_listen = Prompt.ask("Listen address", default=state.listen_address).strip()

    socks = new_socks if new_socks != state.socks_port else None
    http = new_http if new_http != state.http_port else None
    listen = new_listen if new_listen and new_listen != state.listen_address else None
    if login == "keep" and socks is None and http is None and listen is None:
        console.print("[dim]Nothing changed.[/dim]")
        return
    _safe(apply_settings, socks=socks, http=http, listen=listen, user=user, password=None, no_auth=login == "none", yes=False)


def _add_subscription_flow() -> None:
    from v2rm.cli.sub import add_subscription

    url = Prompt.ask("Subscription URL")
    if url:
        _safe(add_subscription, url, name=None, user_agent=None, proxy=None)


def _test_flow() -> None:
    profile = _pick_profile("Test profile #")
    if profile is not None:
        _safe(test_command, profile.id, all_profiles=False, protocol=None, subscription=None, concurrency=4, timeout=10.0)


def _list_profiles_flow() -> None:
    from v2rm.cli.profile import list_profiles

    _safe(list_profiles, subscription=None, protocol=None)


def _remove_profile_flow() -> None:
    from v2rm.cli.profile import remove_profile

    profile = _pick_profile("Remove profile #")
    if profile is not None:
        # yes=False/force=False: reuses remove_profile's own confirmation
        # prompt and its refusal to drop the currently connected profile,
        # same as running `v2rm profile remove` directly.
        _safe(remove_profile, profile.id, yes=False, force=False)


def _remove_subscription_flow() -> None:
    from v2rm.cli.sub import remove_subscription

    sub = _pick_subscription("Remove subscription #")
    if sub is not None:
        _safe(remove_subscription, sub.id, yes=False)


def _update_one_subscription_flow() -> None:
    sub = _pick_subscription("Update subscription #")
    if sub is not None:
        _safe(update_subscription, sub.id, all_subs=False, proxy=None, force=False, respect_interval=False)


def run_menu() -> None:
    """A thin interactive front-end over the same commands available on the
    command line -- every action here calls the identical underlying
    function its `v2rm <command>` equivalent does, so there's no separate
    menu-only logic to keep in sync. Everything stays fully scriptable via
    the plain subcommands directly; this is just a friendlier on-ramp,
    launched automatically when `v2rm` is run with no arguments."""
    console.print(
        "[bold]v2rm[/bold] -- interactive menu. "
        "Everything here is also a plain command; run `v2rm --help` to see them."
    )

    actions = {
        "1": ("Connect / switch profile", _connect_flow),
        "2": ("Disconnect", lambda: _safe(disconnect_command)),
        "3": ("Status", lambda: _safe(status_command)),
        "4": ("List profiles", _list_profiles_flow),
        "5": ("Add a link", _add_link_flow),
        "6": ("Add a subscription", _add_subscription_flow),
        "7": ("Add a JSON config", _add_json_flow),
        "8": ("Add a MASQUE server", _add_masque_flow),
        "9": ("Remove a profile", _remove_profile_flow),
        "10": ("Remove a subscription", _remove_subscription_flow),
        "11": ("Test a profile", _test_flow),
        "12": (
            "Test all profiles",
            lambda: _safe(
                test_command, None, all_profiles=True, protocol=None, subscription=None, concurrency=4, timeout=10.0
            ),
        ),
        "13": ("Update a subscription", _update_one_subscription_flow),
        "14": (
            "Update all subscriptions",
            lambda: _safe(
                update_subscription, None, all_subs=True, proxy=None, force=False, respect_interval=False
            ),
        ),
        "15": ("Add an Aether (Cloudflare WARP) connection", _add_aether_flow),
        "16": ("Make a chain of connections", _add_chain_flow),
        "17": ("Local proxy: ports, listen address, user name and password", _proxy_settings_flow),
    }

    try:
        while True:
            console.print()
            _print_status_line()
            console.print()
            for key, (label, _fn) in actions.items():
                console.print(f"  {key}) {label}")
            console.print("  0) Quit")
            console.print()

            choice = Prompt.ask("Choose", default="0").strip()
            if choice == "0":
                break
            action = actions.get(choice)
            if action is None:
                console.print("[yellow]Not a valid choice.[/yellow]")
                continue
            action[1]()
    except (KeyboardInterrupt, EOFError):
        console.print()
    console.print("[dim]Goodbye.[/dim]")
