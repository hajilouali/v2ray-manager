from __future__ import annotations

from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed

import typer
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from v2rm.constants import CONNECT_POLL_TIMEOUT
from v2rm.engines import resolve_engine
from v2rm.engines.xray.raw import profile_is_serverless
from v2rm.errors import V2rmError
from v2rm.models.auth import ProxyAuth
from v2rm.models.enums import EngineKind
from v2rm.models.profile import Profile
from v2rm.net.ports import free_port
from v2rm.net.speedtest import TestResult, run_connectivity_test
from v2rm.process import stack, supervisor
from v2rm.routing.presets import GLOBAL
from v2rm.store.auth import AuthStore
from v2rm.store.profiles import ProfileStore
from v2rm.store.state import AppStateStore

console = Console()

SERVERLESS_NOTE = (
    "Note: a config without a remote server connects directly and only evades DPI (for example by "
    "fragmenting TLS hellos). A passing test means that direct connection works -- it is not a tunnel, "
    "and it does not hide your IP address."
)


AETHER_TEST_NOTE = (
    "Testing an Aether connection starts its tunnel: Aether looks for a working gateway first, which can "
    "take a minute or two on a filtered network."
)

_free_port = free_port


def _progress(line: str) -> None:
    console.print(f"  [dim]{escape(line)}[/dim]")


def _test_one(
    profile: Profile,
    timeout: float,
    preferred_engine: EngineKind | None = None,
    auth: ProxyAuth | None = None,
    notes: list[str] | None = None,
    progress: Callable[[str], None] | None = None,
) -> TestResult:
    """Always tests through a fresh, throwaway engine instance on ephemeral
    ports -- forced to the 'global' routing preset so the result reflects
    the profile itself, not a bypass rule -- rather than reusing the live
    connection. Slightly more work when the profile happens to already be
    connected, but it never risks disturbing that connection and stays
    safe to run several of these at once for `--all`. The throwaway proxy
    requires the same login as the real one, and the test sends it."""
    if stack.uses_stack(profile):
        return _test_stack(profile, timeout, preferred_engine, auth, notes, progress)

    engine, _ = resolve_engine(profile, preferred_engine)

    socks_port = _free_port()
    http_port = _free_port(avoid=socks_port)

    try:
        with supervisor.run_temporary(
            profile, engine, GLOBAL, socks_port, http_port, start_timeout=CONNECT_POLL_TIMEOUT, auth=auth, notes=notes
        ):
            return run_connectivity_test(socks_port, timeout=timeout, auth=auth)
    except V2rmError as exc:
        return TestResult(ok=False, error=str(exc))


def _test_stack(
    profile: Profile,
    timeout: float,
    preferred_engine: EngineKind | None,
    auth: ProxyAuth | None,
    notes: list[str] | None,
    progress: Callable[[str], None] | None,
) -> TestResult:
    """An Aether profile or a chain. One WARP identity can carry one live tunnel, so a profile
    that is connected right now is tested through its live proxy instead of a second tunnel,
    and one that shares an identity with the live connection is not tested at all."""
    store = ProfileStore()
    live = supervisor.status()
    if live.get("connected"):
        loopback = supervisor.client_address(str(live.get("listen_address", "127.0.0.1"))) == "127.0.0.1"
        if live.get("profile_id") == profile.id and live.get("state") != "starting" and loopback:
            try:
                live_auth = auth if live.get("authenticated") else None
                return run_connectivity_test(int(live["socks_port"]), timeout=timeout, auth=live_auth)
            except V2rmError as exc:
                return TestResult(ok=False, error=str(exc))
        shared = set(live.get("aether_ids") or []) & set(stack.aether_profile_ids(profile, store))
        if shared or live.get("profile_id") == profile.id:
            return TestResult(
                ok=False,
                error=(
                    f"not tested: '{live.get('profile_name', 'the live connection')}' is running with the same WARP "
                    "identity, and two tunnels can't share one. Test it with `v2rm status` / curl through the live "
                    "proxy, or disconnect first."
                ),
            )

    socks_port = _free_port()
    http_port = _free_port(avoid=socks_port)
    try:
        with supervisor.run_temporary_stack(
            profile,
            preferred_engine,
            socks_port,
            http_port,
            start_timeout=CONNECT_POLL_TIMEOUT,
            auth=auth,
            notes=notes,
            progress=progress,
            store=store,
        ):
            return run_connectivity_test(socks_port, timeout=timeout, auth=auth)
    except V2rmError as exc:
        return TestResult(ok=False, error=str(exc))


def test_command(
    ref: str | None = typer.Argument(None, help="Profile id or name to test."),
    all_profiles: bool = typer.Option(False, "--all", help="Test every profile."),
    protocol: str | None = typer.Option(None, "--protocol", help="With --all, only test this protocol."),
    subscription: str | None = typer.Option(
        None, "--subscription", help="With --all, only test this subscription's profiles."
    ),
    concurrency: int = typer.Option(4, "--concurrency", help="With --all, how many tests to run in parallel."),
    timeout: float = typer.Option(10.0, "--timeout", help="Per-test timeout in seconds."),
) -> None:
    """Really test a profile: connect through it and download a small file."""
    store = ProfileStore()
    preferred = AppStateStore().load().active_engine
    auth = AuthStore().load()

    if all_profiles:
        profiles = store.list()
        if protocol:
            profiles = [p for p in profiles if protocol in (p.protocol.value, p.type_label)]
        if subscription:
            from v2rm.store.subscriptions import SubscriptionStore

            sub = SubscriptionStore().resolve(subscription)
            profiles = [p for p in profiles if p.subscription_id == sub.id]
        if not profiles:
            console.print("[yellow]No profiles to test.[/yellow]")
            return
        _run_batch(profiles, concurrency, timeout, preferred, auth)
        return

    if not ref:
        raise V2rmError("Specify a profile id/name, or --all")
    profile = store.resolve(ref)
    notes: list[str] = []
    if stack.uses_stack(profile) and stack.aether_profile_ids(profile, store):
        console.print(f"[dim]{AETHER_TEST_NOTE}[/dim]")
    result = _test_one(profile, timeout, preferred, auth, notes, progress=_progress)
    _print_single(profile, result)
    for note in notes:
        console.print(f"[yellow]Note:[/yellow] {escape(note)}")
    if profile_is_serverless(profile):
        console.print(f"[dim]{escape(SERVERLESS_NOTE)}[/dim]")


def _print_single(profile: Profile, result: TestResult) -> None:
    name = escape(profile.name)
    if result.ok:
        console.print(
            f"[green]OK[/green] {name} -- {result.latency_ms:.0f} ms, "
            f"{result.throughput_mbps:.2f} Mbps [dim](via {escape(str(result.url))})[/dim]"
        )
    else:
        console.print(f"[red]FAIL[/red] {name} -- {escape(str(result.error))}")


def _run_batch(
    profiles: list[Profile],
    concurrency: int,
    timeout: float,
    preferred: EngineKind | None = None,
    auth: ProxyAuth | None = None,
) -> None:
    results: dict[str, TestResult] = {}
    console.print(f"Testing {len(profiles)} profile(s) with concurrency {concurrency}...")

    with ThreadPoolExecutor(max_workers=max(1, concurrency)) as pool:
        futures = {pool.submit(_test_one, p, timeout, preferred, auth): p for p in profiles}
        for future in as_completed(futures):
            p = futures[future]
            results[p.id] = future.result()

    ranked = sorted(
        profiles,
        key=lambda p: (not results[p.id].ok, results[p.id].latency_ms if results[p.id].ok else float("inf")),
    )

    table = Table()
    table.add_column("Name")
    table.add_column("Type")
    table.add_column("Server")
    table.add_column("Latency")
    table.add_column("Speed")
    table.add_column("Result")

    for p in ranked:
        r = results[p.id]
        name, kind, server = escape(p.name), p.type_label, escape(p.server_display)
        if r.ok:
            table.add_row(
                name, kind, server, f"{r.latency_ms:.0f} ms", f"{r.throughput_mbps:.2f} Mbps", "[green]OK[/green]"
            )
        else:
            table.add_row(name, kind, server, "-", "-", f"[red]FAIL[/red] [dim]{escape(str(r.error))}[/dim]")

    console.print(table)
    if any(profile_is_serverless(p) for p in profiles):
        console.print(f"[dim]{escape(SERVERLESS_NOTE)}[/dim]")
