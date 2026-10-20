"""`v2rm chain`: connections strung together, each leaving through the one before it.

A chain is a profile like any other: `v2rm connect NAME`, `v2rm test NAME`, `v2rm profile use`,
`v2rm profile rename` and `v2rm profile remove` all work on it.
"""

from __future__ import annotations

import typer
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from v2rm.engines import resolve_engine
from v2rm.errors import ProfileValidationError, V2rmError
from v2rm.models.chain import HOP_PROFILE, HOP_PROXY, ChainHop
from v2rm.models.enums import Protocol
from v2rm.models.profile import Profile
from v2rm.net.ports import free_port
from v2rm.net.proxy_url import parse_proxy_url
from v2rm.process import stack
from v2rm.routing.presets import GLOBAL
from v2rm.store.profiles import ProfileStore
from v2rm.store.state import AppStateStore

console = Console()
chain_app = typer.Typer(
    help="Chain connections: the traffic of each hop leaves through the one before it, "
    "e.g. `v2rm chain add warp-then-vless \"WARP masque\" my-vless`."
)

PROXY_SCHEMES = ("socks5://", "socks5h://", "socks://", "http://", "https://")

HOW_TO_WRITE_HOPS = (
    "Hops are listed the way the traffic travels: the first is closest to you, the last is what the internet sees. "
    "A hop is a saved profile (name or id) or a proxy already running here (socks5://127.0.0.1:1080)."
)


def parse_hop(ref: str, store: ProfileStore) -> ChainHop:
    """A saved profile, or -- when it is written as a proxy URL -- a proxy that is already running."""
    text = ref.strip()
    if "://" in text:
        if not text.lower().startswith(PROXY_SCHEMES):
            raise V2rmError(f"'{text}' is neither a saved profile nor a proxy address (socks5://host:port or http://host:port)")
        parse_proxy_url(text)  # validated now, not at connect time
        return ChainHop(HOP_PROXY, text)
    member = store.resolve(text)
    return ChainHop(HOP_PROFILE, member.id, member.name)


def build_chain(name: str, hop_refs: list[str], store: ProfileStore | None = None) -> Profile:
    """A validated chain profile (not stored). Raises V2rmError with the reason it can't run."""
    store = store or ProfileStore()
    name = name.strip()
    if not name:
        raise V2rmError("A chain needs a name.")
    if len(hop_refs) < 2:
        raise V2rmError(f"A chain needs at least two hops. {HOW_TO_WRITE_HOPS}")
    if any(p.name == name for p in store.list()):
        raise V2rmError(f"A profile named '{name}' already exists; choose another name for the chain.")

    chain = Profile(name=name, protocol=Protocol.CHAIN, chain=[parse_hop(ref, store) for ref in hop_refs])
    try:
        stack.check_composition(stack.resolve_hops(chain, store), name)
    except ProfileValidationError as exc:
        raise V2rmError(str(exc)) from exc
    return chain


def add_chain(name: str, hop_refs: list[str]) -> Profile:
    """Make and store a chain (a plain function: the menu calls it too)."""
    chain = build_chain(name, hop_refs)
    (stored,) = ProfileStore().add_many([chain])
    console.print(
        f"[green]+[/green] {escape(stored.name)} [dim](chain, {escape(stored.server_display)}, id {stored.id})[/dim]"
    )
    console.print(f"  [dim]Connect it with `v2rm connect {escape(stored.name)}`.[/dim]")
    return stored


def chains_using(profile_id: str, store: ProfileStore | None = None) -> list[Profile]:
    """The chains that have this profile as a hop."""
    store = store or ProfileStore()
    return [
        p for p in store.list() if p.is_chain and any(h.kind == HOP_PROFILE and h.ref == profile_id for h in p.chain or [])
    ]


@chain_app.command("add")
def add_command(
    name: str = typer.Argument(..., help="Name for the chain."),
    hops: list[str] = typer.Argument(..., help="The hops, first (closest to you) to last. " + HOW_TO_WRITE_HOPS),
) -> None:
    """Make a chain out of saved profiles (and, first, optionally a proxy already running here)."""
    add_chain(name, list(hops))


@chain_app.command("list")
def list_command() -> None:
    """List the chains."""
    store = ProfileStore()
    chains = [p for p in store.list() if p.is_chain]
    table = Table()
    table.add_column("ID")
    table.add_column("Name")
    table.add_column("Hops (first -> last)")
    table.add_column("Runnable")
    for chain in chains:
        try:
            stack.check_composition(stack.resolve_hops(chain, store), chain.name)
            runnable = "[green]yes[/green]"
        except V2rmError as exc:
            runnable = f"[red]no[/red] [dim]{escape(str(exc))}[/dim]"
        table.add_row(chain.id, escape(chain.name), escape(chain.server_display), runnable)
    console.print(table)
    if not chains:
        console.print("[dim]No chains yet. Make one with `v2rm chain add NAME HOP HOP ...`.[/dim]")


@chain_app.command("show")
def show_command(ref: str = typer.Argument(..., help="Chain id or name.")) -> None:
    """Show a chain: its hops, which program runs each, and who listens where."""
    store = ProfileStore()
    chain = store.resolve(ref)
    if not chain.is_chain:
        raise V2rmError(f"'{chain.name}' is not a chain; use `v2rm profile show` for it.")

    console.print(f"[bold]{escape(chain.name)}[/bold] [dim]({chain.id})[/dim]")
    state = AppStateStore().load()
    broken = False
    for number, hop in enumerate(chain.chain or [], start=1):
        position = "closest to you" if number == 1 else "what the internet sees" if number == len(chain.chain or []) else ""
        suffix = f"  [dim]{position}[/dim]" if position else ""
        if hop.is_proxy:
            console.print(f"  {number}. {escape(hop.label())}  [dim](a proxy already running)[/dim]{suffix}")
            continue
        member = store.get(hop.ref)
        if member is None:
            broken = True
            console.print(f"  {number}. [red]{escape(hop.label())} -- no longer exists[/red]{suffix}")
            continue
        engine, _ = resolve_engine(member, state.active_engine)
        what = "aether" if member.is_aether else member.type_label
        console.print(
            f"  {number}. {escape(member.name)}  [dim]({what}, {escape(member.server_display)}; runs on {engine.value})[/dim]{suffix}"
        )
    if broken:
        console.print("[red]This chain can't run until the missing profile is replaced.[/red]")
        return

    try:
        plan = stack.plan_stack(
            chain,
            store,
            preferred_engine=state.active_engine,
            route_plan=GLOBAL,
            socks_port=state.socks_port,
            http_port=state.http_port,
            listen_address=state.listen_address,
            auth=None,
            ports=free_port,
        )
    except V2rmError as exc:
        console.print(f"[red]This chain can't run:[/red] {escape(str(exc))}")
        return

    console.print(f"  traffic: you -> {escape(' -> '.join(plan.hops))} -> the internet")
    console.print("  programs, in the order they start:")
    for stage in plan.stages:
        role = f"serves {state.listen_address}:{stage.socks_port}" if stage.user_facing else f"loopback port {stage.socks_port}"
        console.print(f"    - {escape(stage.label)}  [dim]({role})[/dim]")
    for note in plan.notes:
        console.print(f"  [yellow]Note:[/yellow] {escape(note)}")


@chain_app.command("remove")
def remove_command(
    ref: str = typer.Argument(..., help="Chain id or name."),
    yes: bool = typer.Option(False, "--yes", "-y", help="Don't ask for confirmation."),
    force: bool = typer.Option(False, "--force", help="Remove even if it's the currently connected profile."),
) -> None:
    """Remove a chain (the profiles in it are kept)."""
    from v2rm.cli.profile import remove_profile

    chain = ProfileStore().resolve(ref)
    if not chain.is_chain:
        raise V2rmError(f"'{chain.name}' is not a chain; use `v2rm profile remove` for it.")
    remove_profile(chain.id, yes=yes, force=force)

