from __future__ import annotations

import typer
from rich.console import Console
from rich.prompt import IntPrompt, Prompt

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
        console.print(f"[bold red]Error:[/bold red] {exc}")
    except typer.Exit:
        pass


def _print_status_line() -> None:
    info = supervisor.status()
    if info.get("connected"):
        console.print(f"[bold green]Connected[/bold green] via {info.get('engine')} -> {info.get('profile_name')}")
    else:
        console.print("[dim]Not connected[/dim]")


def _pick_profile(prompt: str) -> Profile | None:
    profiles = ProfileStore().list()
    if not profiles:
        console.print("[yellow]No profiles yet -- add one first.[/yellow]")
        return None

    for i, p in enumerate(profiles, start=1):
        console.print(f"  {i}) {p.name} [dim]({p.protocol.value}, {p.server_display})[/dim]")
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
        console.print(f"  {i}) {s.name} [dim]({s.url})[/dim]")
    idx = IntPrompt.ask(prompt, default=0)
    if idx < 1 or idx > len(subs):
        return None
    return subs[idx - 1]


def _connect_flow() -> None:
    profile = _pick_profile("Connect to profile #")
    if profile is not None:
        _safe(connect_command, profile.id)


def _add_link_flow() -> None:
    from v2rm.cli.add import add_command

    link = Prompt.ask("Paste a share link")
    if link:
        _safe(add_command, link, file=None)


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
        _safe(update_subscription, sub.id, all_subs=False, proxy=None, force=False)


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
        "7": ("Remove a profile", _remove_profile_flow),
        "8": ("Remove a subscription", _remove_subscription_flow),
        "9": ("Test a profile", _test_flow),
        "10": (
            "Test all profiles",
            lambda: _safe(
                test_command, None, all_profiles=True, protocol=None, subscription=None, concurrency=4, timeout=10.0
            ),
        ),
        "11": ("Update a subscription", _update_one_subscription_flow),
        "12": (
            "Update all subscriptions",
            lambda: _safe(update_subscription, None, all_subs=True, proxy=None, force=False),
        ),
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
