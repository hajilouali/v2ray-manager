from __future__ import annotations

from urllib.parse import urlsplit

import typer
from rich.console import Console
from rich.table import Table

from v2rm.errors import V2rmError
from v2rm.models.enums import ProfileSource, SubscriptionFormat
from v2rm.models.profile import Profile, now_iso
from v2rm.models.subscription import Subscription
from v2rm.parsers import parse_links
from v2rm.parsers.links import b64_decode_text
from v2rm.store.profiles import ProfileStore
from v2rm.store.state import AppStateStore
from v2rm.store.subscriptions import SubscriptionStore
from v2rm.subscription.clash_yaml import parse_clash_yaml
from v2rm.subscription.detect import detect_format
from v2rm.subscription.fetch import fetch_subscription_body
from v2rm.subscription.sync import diff_subscription_members

console = Console()
sub_app = typer.Typer(help="Manage subscriptions (multi-profile links that can be refreshed).")


def _parse_body(text: str) -> tuple[list[Profile], list[tuple[str, str]], SubscriptionFormat]:
    fmt = detect_format(text)
    if fmt == SubscriptionFormat.CLASH_YAML:
        profiles, errors = parse_clash_yaml(text)
        return profiles, errors, fmt

    body = b64_decode_text(text) if fmt == SubscriptionFormat.BASE64_LIST else text
    profiles, errors = parse_links(body)
    return profiles, errors, fmt


@sub_app.command("add")
def add_subscription(
    url: str = typer.Argument(..., help="Subscription URL."),
    name: str | None = typer.Option(None, "--name", help="Display name (defaults to the URL's host)."),
    user_agent: str | None = typer.Option(
        None, "--user-agent", help="Override the User-Agent sent when fetching."
    ),
    proxy: str | None = typer.Option(
        None, "--proxy", help="Fetch through this proxy, e.g. socks5://127.0.0.1:10808."
    ),
) -> None:
    """Add a subscription and fetch its member profiles."""
    display_name = name or urlsplit(url).hostname or url
    sub = Subscription(name=display_name, url=url, user_agent=user_agent)

    text = fetch_subscription_body(url, user_agent=user_agent, proxy=proxy)
    profiles, errors, fmt = _parse_body(text)

    for p in profiles:
        p.source = ProfileSource.SUBSCRIPTION
        p.subscription_id = sub.id

    sub.format_hint = fmt
    sub.profile_ids = [p.id for p in profiles]
    sub.last_updated = now_iso()
    sub.last_status = "ok" if not errors else f"ok with {len(errors)} error(s)"

    SubscriptionStore().add(sub)
    if profiles:
        ProfileStore().add_many(profiles)

    console.print(f"[green]Added subscription[/green] {sub.name} [dim]({sub.id})[/dim] -- {len(profiles)} profile(s)")
    for line, message in errors:
        shown = line if len(line) <= 60 else line[:57] + "..."
        console.print(f"[red]x[/red] {shown} [dim]-> {message}[/dim]")


@sub_app.command("update")
def update_subscription(
    ref: str | None = typer.Argument(None, help="Subscription id or name. Omit with --all."),
    all_subs: bool = typer.Option(False, "--all", help="Update every subscription."),
    proxy: str | None = typer.Option(None, "--proxy", help="Fetch through this proxy."),
    force: bool = typer.Option(False, "--force", help="Allow removing the currently connected profile."),
) -> None:
    """Re-fetch subscription(s) and sync their member profiles."""
    sub_store = SubscriptionStore()
    profile_store = ProfileStore()
    state = AppStateStore().load()

    if all_subs:
        targets = sub_store.list()
    elif ref:
        targets = [sub_store.resolve(ref)]
    else:
        raise V2rmError("Specify a subscription id/name, or --all")

    for sub in targets:
        console.print(f"Updating [bold]{sub.name}[/bold]...")
        try:
            text = fetch_subscription_body(sub.url, user_agent=sub.user_agent, proxy=proxy)
            fetched, errors, fmt = _parse_body(text)
        except Exception as exc:  # noqa: BLE001 - one subscription's failure must not abort the rest of --all
            sub.last_status = f"error: {exc}"
            sub_store.update(sub)
            console.print(f"  [red]Failed:[/red] {exc}")
            continue

        existing = profile_store.list_by_subscription(sub.id)
        result = diff_subscription_members(existing, fetched)

        if state.active_profile_id in result.removed_ids and not force:
            console.print(
                "  [yellow]Skipped removing the active/connected profile.[/yellow] "
                "Re-run with --force to remove it anyway."
            )
            result.removed_ids = [i for i in result.removed_ids if i != state.active_profile_id]

        for p in result.added:
            p.source = ProfileSource.SUBSCRIPTION
            p.subscription_id = sub.id
        if result.added:
            profile_store.add_many(result.added)
        for p in result.updated:
            profile_store.update(p)
        if result.removed_ids:
            profile_store.remove_many(result.removed_ids)

        sub.format_hint = fmt
        sub.profile_ids = [p.id for p in result.added] + [p.id for p in result.updated]
        sub.last_updated = now_iso()
        sub.last_status = "ok" if not errors else f"ok with {len(errors)} error(s)"
        sub_store.update(sub)

        console.print(
            f"  [green]+{len(result.added)}[/green] [cyan]~{len(result.updated)}[/cyan] "
            f"[red]-{len(result.removed_ids)}[/red]"
        )


@sub_app.command("remove")
def remove_subscription(
    ref: str = typer.Argument(..., help="Subscription id or name."),
    yes: bool = typer.Option(False, "--yes", "-y", help="Don't ask for confirmation."),
) -> None:
    """Remove a subscription and all of its member profiles."""
    sub_store = SubscriptionStore()
    profile_store = ProfileStore()
    sub = sub_store.resolve(ref)

    members = profile_store.list_by_subscription(sub.id)
    if not yes and not typer.confirm(f"Remove subscription '{sub.name}' and its {len(members)} profile(s)?"):
        raise typer.Exit()

    profile_store.remove_many(p.id for p in members)
    sub_store.remove(sub.id)
    console.print(f"[green]Removed[/green] {sub.name} and {len(members)} profile(s)")


@sub_app.command("list")
def list_subscriptions() -> None:
    """List subscriptions."""
    sub_store = SubscriptionStore()
    profile_store = ProfileStore()
    subs = sub_store.list()

    table = Table()
    table.add_column("ID")
    table.add_column("Name")
    table.add_column("Profiles")
    table.add_column("Last updated")
    table.add_column("Status")

    for sub in subs:
        count = len(profile_store.list_by_subscription(sub.id))
        table.add_row(sub.id, sub.name, str(count), sub.last_updated or "[dim]never[/dim]", sub.last_status)

    console.print(table)
    if not subs:
        console.print("[dim]No subscriptions yet. Add one with `v2rm sub add <url>`.[/dim]")


@sub_app.command("show")
def show_subscription(ref: str = typer.Argument(..., help="Subscription id or name.")) -> None:
    """Show full detail for a subscription, including its member profiles."""
    sub_store = SubscriptionStore()
    profile_store = ProfileStore()
    sub = sub_store.resolve(ref)
    members = profile_store.list_by_subscription(sub.id)

    console.print(f"[bold]{sub.name}[/bold] [dim]({sub.id})[/dim]")
    console.print(f"  url          {sub.url}")
    console.print(f"  format       {sub.format_hint.value if sub.format_hint else '?'}")
    console.print(f"  last updated {sub.last_updated or 'never'}")
    console.print(f"  status       {sub.last_status}")
    console.print(f"  profiles     {len(members)}")
    for p in members:
        console.print(f"    - {p.name} [dim]({p.protocol.value}, {p.server_display})[/dim]")
