from __future__ import annotations

import typer
from rich.console import Console
from rich.table import Table

from v2rm.coredl import install as installer
from v2rm.errors import DownloadError, V2rmError
from v2rm.models.enums import EngineKind
from v2rm.store.state import AppStateStore

console = Console()
core_app = typer.Typer(help="Manage the Xray-core and sing-box engine binaries.")

_ENGINES = ("xray", "singbox")


def _check_engine(engine: str) -> None:
    if engine not in _ENGINES:
        raise V2rmError(f"Unknown engine '{engine}'. Choose one of: {', '.join(_ENGINES)}")


@core_app.command("list")
def list_engines() -> None:
    """Show installed engine versions and which one is active."""
    state = AppStateStore().load()
    table = Table()
    table.add_column("Engine")
    table.add_column("Installed versions")
    table.add_column("Current")
    table.add_column("Active in v2rm")

    for engine in _ENGINES:
        versions = installer.installed_versions(engine)
        current = installer.current_version(engine)
        active = state.active_engine is not None and state.active_engine.value == engine
        table.add_row(
            engine,
            ", ".join(versions) if versions else "[dim]none[/dim]",
            current or "[dim]-[/dim]",
            "[bold green]*[/bold green]" if active else "",
        )
    console.print(table)


@core_app.command("install")
def install_engine(
    engine: str = typer.Argument(..., help="xray or singbox"),
    version: str | None = typer.Option(
        None, "--version", help="Specific release tag, e.g. v26.3.27. Defaults to latest."
    ),
) -> None:
    """Download, verify, and install an engine binary."""
    _check_engine(engine)
    console.print(f"Fetching {engine} release info...")
    try:
        tag = installer.install_xray(version) if engine == "xray" else installer.install_singbox(version)
    except DownloadError as exc:
        raise V2rmError(str(exc)) from exc
    console.print(f"[green]Installed[/green] {engine} {tag}")


@core_app.command("update")
def update_engine(engine: str = typer.Argument(..., help="xray or singbox")) -> None:
    """Install the latest release if it's newer than what's currently active."""
    _check_engine(engine)
    current = installer.current_version(engine)
    console.print(f"Checking latest {engine} release...")
    try:
        tag = installer.install_xray(None) if engine == "xray" else installer.install_singbox(None)
    except DownloadError as exc:
        raise V2rmError(str(exc)) from exc

    if tag == current:
        console.print(f"[dim]{engine} is already up to date ({tag}).[/dim]")
    else:
        console.print(f"[green]Updated[/green] {engine} {current or '(none)'} -> {tag}")


@core_app.command("use")
def use_engine(engine: str = typer.Argument(..., help="xray or singbox")) -> None:
    """Set the default engine for new connections."""
    _check_engine(engine)
    state_store = AppStateStore()
    state = state_store.load()
    state.active_engine = EngineKind(engine)
    state_store.save(state)
    console.print(f"[green]Active engine set to[/green] {engine}")


@core_app.command("remove")
def remove_engine(
    engine: str = typer.Argument(..., help="xray or singbox"),
    version: str | None = typer.Option(None, "--version", help="Specific version to remove."),
    all_versions: bool = typer.Option(False, "--all", help="Remove every installed version."),
    yes: bool = typer.Option(False, "--yes", "-y", help="Don't ask for confirmation."),
) -> None:
    """Remove installed engine version(s)."""
    _check_engine(engine)
    if not version and not all_versions:
        raise V2rmError("Specify --version <tag> or --all")

    targets = installer.installed_versions(engine) if all_versions else [version]
    if not targets:
        console.print("[dim]Nothing to remove.[/dim]")
        return

    if not yes and not typer.confirm(f"Remove {engine} version(s): {', '.join(targets)}?"):
        raise typer.Exit()

    for v in targets:
        try:
            installer.remove_version(engine, v)
            console.print(f"[green]Removed[/green] {engine} {v}")
        except DownloadError as exc:
            console.print(f"[red]Skipped[/red] {v}: {exc}")
