from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

import typer
from rich.console import Console
from rich.table import Table

from v2rm.constants import CONNECT_POLL_TIMEOUT
from v2rm.engines import engine_for_protocol
from v2rm.errors import V2rmError
from v2rm.models.profile import Profile
from v2rm.net.speedtest import TestResult, run_connectivity_test
from v2rm.process import supervisor
from v2rm.routing.presets import GLOBAL
from v2rm.store.profiles import ProfileStore

console = Console()


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _test_one(profile: Profile, timeout: float) -> TestResult:
    """Always tests through a fresh, throwaway engine instance on ephemeral
    ports -- forced to the 'global' routing preset so the result reflects
    the profile itself, not a bypass rule -- rather than reusing the live
    connection. Slightly more work when the profile happens to already be
    connected, but it never risks disturbing that connection and stays
    safe to run several of these at once for `--all`."""
    try:
        engine = engine_for_protocol(profile.protocol)
    except ValueError as exc:
        return TestResult(ok=False, error=str(exc))

    socks_port = _free_port()
    http_port = _free_port()

    try:
        with supervisor.run_temporary(profile, engine, GLOBAL, socks_port, http_port, start_timeout=CONNECT_POLL_TIMEOUT):
            return run_connectivity_test(socks_port, timeout=timeout)
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

    if all_profiles:
        profiles = store.list()
        if protocol:
            profiles = [p for p in profiles if p.protocol.value == protocol]
        if subscription:
            from v2rm.store.subscriptions import SubscriptionStore

            sub = SubscriptionStore().resolve(subscription)
            profiles = [p for p in profiles if p.subscription_id == sub.id]
        if not profiles:
            console.print("[yellow]No profiles to test.[/yellow]")
            return
        _run_batch(profiles, concurrency, timeout)
        return

    if not ref:
        raise V2rmError("Specify a profile id/name, or --all")
    profile = store.resolve(ref)
    result = _test_one(profile, timeout)
    _print_single(profile, result)


def _print_single(profile: Profile, result: TestResult) -> None:
    if result.ok:
        console.print(
            f"[green]OK[/green] {profile.name} -- {result.latency_ms:.0f} ms, "
            f"{result.throughput_mbps:.2f} Mbps [dim](via {result.url})[/dim]"
        )
    else:
        console.print(f"[red]FAIL[/red] {profile.name} -- {result.error}")


def _run_batch(profiles: list[Profile], concurrency: int, timeout: float) -> None:
    results: dict[str, TestResult] = {}
    console.print(f"Testing {len(profiles)} profile(s) with concurrency {concurrency}...")

    with ThreadPoolExecutor(max_workers=max(1, concurrency)) as pool:
        futures = {pool.submit(_test_one, p, timeout): p for p in profiles}
        for future in as_completed(futures):
            p = futures[future]
            results[p.id] = future.result()

    ranked = sorted(
        profiles,
        key=lambda p: (not results[p.id].ok, results[p.id].latency_ms if results[p.id].ok else float("inf")),
    )

    table = Table()
    table.add_column("Name")
    table.add_column("Protocol")
    table.add_column("Server")
    table.add_column("Latency")
    table.add_column("Speed")
    table.add_column("Result")

    for p in ranked:
        r = results[p.id]
        if r.ok:
            table.add_row(
                p.name, p.protocol.value, p.server_display, f"{r.latency_ms:.0f} ms", f"{r.throughput_mbps:.2f} Mbps",
                "[green]OK[/green]",
            )
        else:
            table.add_row(
                p.name, p.protocol.value, p.server_display, "-", "-", f"[red]FAIL[/red] [dim]{r.error}[/dim]"
            )

    console.print(table)
