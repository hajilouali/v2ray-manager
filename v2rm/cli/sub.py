from __future__ import annotations

from datetime import datetime, timezone
from urllib.parse import unquote, urlsplit, urlunsplit

import typer
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from v2rm.errors import V2rmError
from v2rm.models.enums import ProfileSource, SubscriptionFormat
from v2rm.models.profile import Profile, now_iso
from v2rm.models.subscription import Subscription
from v2rm.parsers import parse_links
from v2rm.parsers.links import b64_decode_text
from v2rm.parsers.raw import parse_xray_json
from v2rm.store.profiles import ProfileStore
from v2rm.store.state import AppStateStore
from v2rm.store.subscriptions import SubscriptionStore
from v2rm.subscription.clash_yaml import parse_clash_yaml
from v2rm.subscription.detect import detect_format
from v2rm.subscription.fetch import fetch_subscription_body
from v2rm.subscription.meta import SubscriptionMeta, parse_meta, strip_comment_lines
from v2rm.subscription.sync import diff_subscription_members

console = Console()
sub_app = typer.Typer(help="Manage subscriptions (multi-profile links that can be refreshed).")

_MAX_ERRORS_SHOWN = 10
_MAX_MEMBERS_SHOWN = 25


def _parse_body(
    text: str,
) -> tuple[list[Profile], list[tuple[str, str]], SubscriptionFormat, SubscriptionMeta]:
    fmt = detect_format(text)
    if fmt == SubscriptionFormat.XRAY_JSON:
        profiles, errors = parse_xray_json(text)
        return profiles, errors, fmt, SubscriptionMeta()
    if fmt == SubscriptionFormat.CLASH_YAML:
        profiles, errors = parse_clash_yaml(text)
        return profiles, errors, fmt, SubscriptionMeta()

    meta = parse_meta(text)
    body = text
    if fmt == SubscriptionFormat.BASE64_LIST:
        body = b64_decode_text(strip_comment_lines(text))
        inner = parse_meta(body)  # the decoded payload may carry the headers instead
        meta.title = meta.title or inner.title
        meta.update_interval_hours = meta.update_interval_hours or inner.update_interval_hours
    profiles, errors = parse_links(body)
    return profiles, errors, fmt, meta


def _print_errors(errors: list[tuple[str, str]]) -> None:
    for line, message in errors[:_MAX_ERRORS_SHOWN]:
        shown = line if len(line) <= 60 else line[:57] + "..."
        console.print(f"[red]x[/red] {escape(shown)} [dim]-> {escape(message)}[/dim]")
    if len(errors) > _MAX_ERRORS_SHOWN:
        console.print(f"[dim]... and {len(errors) - _MAX_ERRORS_SHOWN} more entries that failed to parse[/dim]")


def _short_timestamp(iso: str | None) -> str:
    """2026-10-19T17:37:02+00:00 -> 2026-10-19 17:37 (UTC)."""
    if not iso:
        return "[dim]never[/dim]"
    return iso[:16].replace("T", " ")


def _refreshed_recently(sub: Subscription) -> bool:
    if not sub.update_interval_hours or not sub.last_updated:
        return False
    try:
        last = datetime.fromisoformat(sub.last_updated)
    except ValueError:
        return False
    age_hours = (datetime.now(timezone.utc) - last).total_seconds() / 3600
    return age_hours < sub.update_interval_hours


@sub_app.command("add")
def add_subscription(
    url: str = typer.Argument(
        ..., help="Subscription URL. A trailing #name becomes the subscription's name (it is never sent)."
    ),
    name: str | None = typer.Option(None, "--name", help="Display name (overrides the URL's #name)."),
    user_agent: str | None = typer.Option(
        None, "--user-agent", help="Override the User-Agent sent when fetching."
    ),
    proxy: str | None = typer.Option(
        None, "--proxy", help="Fetch through this proxy, e.g. socks5://127.0.0.1:10808."
    ),
) -> None:
    """Add a subscription and fetch its member profiles.

    Understands base64 and plain link lists (with `#profile-title` /
    `#profile-update-interval` header comments), Clash/Mihomo YAML, and Xray
    JSON (one config or an array of them -> raw profiles)."""
    parts = urlsplit(url)
    fragment_name = unquote(parts.fragment).strip() or None
    fetch_url = urlunsplit(parts._replace(fragment=""))

    text = fetch_subscription_body(fetch_url, user_agent=user_agent, proxy=proxy)
    profiles, errors, fmt, meta = _parse_body(text)

    if not profiles:
        _print_errors(errors)
        raise V2rmError(
            f"No usable profiles found at {fetch_url} (detected format: {fmt.value}"
            + (f", {len(errors)} entries failed to parse" if errors else "")
            + "). Nothing was added."
        )

    display_name = name or fragment_name or meta.title or parts.hostname or fetch_url
    sub = Subscription(name=display_name, url=fetch_url, user_agent=user_agent)

    for p in profiles:
        p.source = ProfileSource.SUBSCRIPTION
        p.subscription_id = sub.id

    sub.format_hint = fmt
    sub.profile_ids = [p.id for p in profiles]
    sub.last_updated = now_iso()
    sub.last_status = "ok" if not errors else f"ok with {len(errors)} error(s)"
    sub.update_interval_hours = meta.update_interval_hours

    SubscriptionStore().add(sub)
    ProfileStore().add_many(profiles)

    console.print(
        f"[green]Added subscription[/green] {escape(sub.name)} [dim]({sub.id}, {fmt.value})[/dim] "
        f"-- {len(profiles)} profile(s)"
    )
    _print_errors(errors)


@sub_app.command("update")
def update_subscription(
    ref: str | None = typer.Argument(None, help="Subscription id or name. Omit with --all."),
    all_subs: bool = typer.Option(False, "--all", help="Update every subscription."),
    proxy: str | None = typer.Option(None, "--proxy", help="Fetch through this proxy."),
    force: bool = typer.Option(
        False,
        "--force",
        help="Allow removing the currently connected profile, and ignore --respect-interval.",
    ),
    respect_interval: bool = typer.Option(
        False,
        "--respect-interval",
        help="With --all: skip subscriptions refreshed more recently than the provider's own "
        "#profile-update-interval (for cron/timer use). Updating a named subscription always refreshes it.",
    ),
) -> None:
    """Re-fetch subscription(s) and sync their member profiles."""
    sub_store = SubscriptionStore()
    profile_store = ProfileStore()
    state = AppStateStore().load()
    profile_store.persist_upgrades()

    if all_subs:
        targets = sub_store.list()
    elif ref:
        targets = [sub_store.resolve(ref)]
    else:
        raise V2rmError("Specify a subscription id/name, or --all")

    for sub in targets:
        if all_subs and respect_interval and not force and _refreshed_recently(sub):
            console.print(
                f"[bold]{escape(sub.name)}[/bold]: [dim]skipped -- refreshed less than "
                f"{sub.update_interval_hours:g}h ago (the provider's own interval); use --force to refresh anyway[/dim]"
            )
            continue

        console.print(f"Updating [bold]{escape(sub.name)}[/bold]...")
        try:
            text = fetch_subscription_body(sub.url, user_agent=sub.user_agent, proxy=proxy)
            fetched, errors, fmt, meta = _parse_body(text)
        except Exception as exc:  # noqa: BLE001 - one subscription's failure must not abort the rest of --all
            sub.last_status = f"error: {exc}"
            sub_store.update(sub)
            console.print(f"  [red]Failed:[/red] {escape(str(exc))}")
            continue

        existing = profile_store.list_by_subscription(sub.id)
        if not fetched and existing:
            # An outage page or truncated response parses to nothing; syncing
            # that would delete every profile the subscription has.
            sub.last_status = f"error: fetched no usable profiles ({len(errors)} parse errors)"
            sub_store.update(sub)
            console.print(
                "  [red]Fetched no usable profiles[/red] -- keeping the existing "
                f"{len(existing)} instead of removing them all."
            )
            _print_errors(errors)
            continue

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
        profile_store.update_many(result.updated)
        if result.removed_ids:
            profile_store.remove_many(result.removed_ids)

        sub.format_hint = fmt
        sub.profile_ids = [p.id for p in result.added] + result.kept_ids
        sub.last_updated = now_iso()
        sub.last_status = "ok" if not errors else f"ok with {len(errors)} error(s)"
        if meta.update_interval_hours:
            sub.update_interval_hours = meta.update_interval_hours
        sub_store.update(sub)

        console.print(
            f"  [green]+{len(result.added)}[/green] [cyan]~{len(result.updated)}[/cyan] "
            f"[red]-{len(result.removed_ids)}[/red] [dim]={result.unchanged}[/dim]"
        )
        _print_errors(errors)


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
    console.print(f"[green]Removed[/green] {escape(sub.name)} and {len(members)} profile(s)")


@sub_app.command("list")
def list_subscriptions() -> None:
    """List subscriptions."""
    sub_store = SubscriptionStore()
    profile_store = ProfileStore()
    subs = sub_store.list()

    table = Table()
    table.add_column("ID", no_wrap=True)
    table.add_column("Name", no_wrap=True)  # never ellipsized: it's the column people look for
    table.add_column("Format", no_wrap=True)
    table.add_column("Profiles", justify="right", no_wrap=True)
    table.add_column("Interval", no_wrap=True)
    table.add_column("Updated", no_wrap=True)
    table.add_column("Status")

    for sub in subs:
        count = len(profile_store.list_by_subscription(sub.id))
        table.add_row(
            sub.id,
            escape(sub.name),
            sub.format_hint.value if sub.format_hint else "?",
            str(count),
            f"{sub.update_interval_hours:g}h" if sub.update_interval_hours else "[dim]-[/dim]",
            _short_timestamp(sub.last_updated),
            escape(sub.last_status),
        )

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

    console.print(f"[bold]{escape(sub.name)}[/bold] [dim]({sub.id})[/dim]")
    console.print(f"  url             {escape(sub.url)}")
    console.print(f"  format          {sub.format_hint.value if sub.format_hint else '?'}")
    interval = f"{sub.update_interval_hours:g}h (provider's refresh hint)" if sub.update_interval_hours else "-"
    console.print(f"  update interval {interval}")
    console.print(f"  last updated    {sub.last_updated or 'never'}")
    console.print(f"  status          {escape(sub.last_status)}")
    console.print(f"  profiles        {len(members)}")
    for p in members[:_MAX_MEMBERS_SHOWN]:
        console.print(f"    - {escape(p.name)} [dim]({p.type_label}, {escape(p.server_display)})[/dim]")
    if len(members) > _MAX_MEMBERS_SHOWN:
        console.print(
            f"    [dim]... and {len(members) - _MAX_MEMBERS_SHOWN} more "
            f"(`v2rm profile list --subscription {escape(sub.name)}`)[/dim]"
        )
