from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import typer
from rich.console import Console

from v2rm.errors import V2rmError
from v2rm.models.profile import Profile
from v2rm.models.state import AppState
from v2rm.models.subscription import Subscription
from v2rm.store import paths
from v2rm.store.profiles import ProfileStore
from v2rm.store.state import AppStateStore
from v2rm.store.subscriptions import SubscriptionStore

console = Console()

_BUNDLE_VERSION = 1


def export_command(
    file: Path | None = typer.Argument(None, help="Output file. Defaults to ./v2rm-backup-<date>.json"),
) -> None:
    """Bundle profiles, subscriptions, custom routes, and app state into one file."""
    if file is None:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        file = Path(f"v2rm-backup-{stamp}.json")

    profiles = [p.to_dict() for p in ProfileStore().list()]
    subscriptions = [s.to_dict() for s in SubscriptionStore().list()]
    state = AppStateStore().load().to_dict()

    custom_routes_text = None
    if paths.custom_routes_file().exists():
        custom_routes_text = paths.custom_routes_file().read_text(encoding="utf-8")

    bundle = {
        "bundle_version": _BUNDLE_VERSION,
        "exported_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "profiles": profiles,
        "subscriptions": subscriptions,
        "state": state,
        "custom_routes_yaml": custom_routes_text,
    }

    file.write_text(json.dumps(bundle, indent=2, ensure_ascii=False), encoding="utf-8")
    console.print(
        f"[green]Exported[/green] {len(profiles)} profile(s), {len(subscriptions)} subscription(s) -> {file}"
    )


def import_command(
    file: Path = typer.Argument(..., help="Backup file created by `v2rm export`."),
    replace: bool = typer.Option(
        False, "--replace", help="Replace all existing profiles/subscriptions instead of merging."
    ),
) -> None:
    """Restore profiles, subscriptions, custom routes, and app state from a backup file."""
    if not file.exists():
        raise V2rmError(f"File not found: {file}")

    try:
        bundle = json.loads(file.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise V2rmError(f"Invalid backup file: {exc}") from exc

    try:
        profiles = [Profile.from_dict(p) for p in bundle.get("profiles", [])]
        subscriptions = [Subscription.from_dict(s) for s in bundle.get("subscriptions", [])]
    except (KeyError, ValueError, TypeError) as exc:
        raise V2rmError(f"Invalid backup file contents: {exc}") from exc

    profile_store = ProfileStore()
    sub_store = SubscriptionStore()

    if replace:
        for p in profile_store.list():
            profile_store.remove(p.id)
        for s in sub_store.list():
            sub_store.remove(s.id)

    # Upsert by id rather than blindly appending, so importing the same
    # backup twice (or a partially-overlapping one) updates in place
    # instead of creating duplicate rows with the same id.
    existing_profile_ids = {p.id for p in profile_store.list()}
    existing_sub_ids = {s.id for s in sub_store.list()}

    new_profiles = [p for p in profiles if p.id not in existing_profile_ids]
    updated_profiles = [p for p in profiles if p.id in existing_profile_ids]
    if new_profiles:
        profile_store.add_many(new_profiles)
    for p in updated_profiles:
        profile_store.update(p)

    new_subs = [s for s in subscriptions if s.id not in existing_sub_ids]
    updated_subs = [s for s in subscriptions if s.id in existing_sub_ids]
    for s in new_subs:
        sub_store.add(s)
    for s in updated_subs:
        sub_store.update(s)

    if bundle.get("custom_routes_yaml"):
        paths.routes_dir().mkdir(parents=True, exist_ok=True)
        paths.custom_routes_file().write_text(bundle["custom_routes_yaml"], encoding="utf-8")

    if replace and bundle.get("state"):
        AppStateStore().save(AppState.from_dict(bundle["state"]))

    console.print(
        f"[green]Imported[/green] {len(new_profiles)} new + {len(updated_profiles)} updated profile(s), "
        f"{len(new_subs)} new + {len(updated_subs)} updated subscription(s) from {file}"
    )
