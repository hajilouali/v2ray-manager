from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from v2rm.coredl import install as installer
from v2rm.coredl.github import AETHER_VARIANTS
from v2rm.engines.versioning import compare_versions
from v2rm.errors import DownloadError, V2rmError
from v2rm.models.enums import EngineKind
from v2rm.store.state import AppStateStore

console = Console()
core_app = typer.Typer(help="Manage the Xray-core, sing-box and Aether engine binaries.")

_ENGINES = ("xray", "singbox", "aether")
# What `core use` can make the default for ordinary profiles. Aether only runs Aether profiles.
_DEFAULT_ENGINES = ("xray", "singbox")


def _check_engine(engine: str) -> None:
    if engine not in _ENGINES:
        raise V2rmError(f"Unknown engine '{engine}'. Choose one of: {', '.join(_ENGINES)}")


def _check_variant(engine: str, variant: str | None) -> str | None:
    if variant is None:
        return None
    if engine != "aether":
        raise V2rmError("--variant only applies to aether.")
    if variant.lower() not in AETHER_VARIANTS:
        raise V2rmError(f"Unknown --variant '{variant}'. Choose one of: {', '.join(AETHER_VARIANTS)}")
    return variant.lower()


_VARIANT_HELP = (
    "Aether only: 'musl' (default; a static build that runs on any Linux) or 'gnu' (needs a recent glibc)."
)


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
        # Xray unless `core use` said otherwise; Aether is never the default, it serves its own profiles.
        active = engine in _DEFAULT_ENGINES and (state.active_engine or EngineKind.XRAY).value == engine
        table.add_row(
            engine,
            ", ".join(versions) if versions else "[dim]none[/dim]",
            current or "[dim]-[/dim]",
            "[bold green]*[/bold green]" if active else "",
        )
    console.print(table)


_PRE_HELP = (
    "Include pre-releases. Xray-core currently publishes its newest builds only as "
    "pre-releases, so without this you get an older stable one."
)


@core_app.command("install")
def install_engine(
    engine: str = typer.Argument(..., help="xray, singbox or aether"),
    version: str | None = typer.Option(
        None, "--version", help="Specific release tag, e.g. v26.3.27 (pre-releases work too). Defaults to latest."
    ),
    pre: bool = typer.Option(False, "--pre", help=_PRE_HELP),
    variant: str | None = typer.Option(None, "--variant", help=_VARIANT_HELP),
    from_file: Path | None = typer.Option(
        None,
        "--from-file",
        help="Install from a release archive you already have (downloaded on a faster link and copied over, "
        "say) instead of downloading. Needs --version; add --sha256 to have it verified.",
    ),
    sha256: str | None = typer.Option(None, "--sha256", help="With --from-file: the archive's expected SHA-256."),
) -> None:
    """Download, verify, and install an engine binary."""
    _check_engine(engine)
    chosen = _check_variant(engine, variant)
    if version and pre:
        raise V2rmError("Use either --version or --pre, not both.")
    if sha256 and from_file is None:
        raise V2rmError("--sha256 goes with --from-file.")
    if from_file is not None:
        if pre:
            raise V2rmError("--pre doesn't apply to --from-file; name the release with --version.")
        try:
            tag, digest = installer.install_from_file(engine, from_file, version or "", sha256, chosen)
        except DownloadError as exc:
            raise V2rmError(str(exc)) from exc
        console.print(f"[green]Installed[/green] {engine} {tag} from {escape(str(from_file))}")
        console.print(f"  sha256 {digest}")
        if not sha256:
            console.print(
                "  [yellow]Nothing verified this file.[/yellow] Compare that digest with the one the release publishes "
                "(the .sha256 file beside the asset, or SHA256SUMS.txt), or pass --sha256 next time."
            )
        return
    console.print(f"Fetching {engine} release info...")
    try:
        release = installer.fetch_release_for(engine, version, pre)
        kind = " (pre-release)" if release.prerelease else ""
        console.print(f"Release: {release.tag}{kind}")
        tag = installer.install_engine(engine, release, progress=console.print, variant=chosen)
    except DownloadError as exc:
        raise V2rmError(str(exc)) from exc
    console.print(f"[green]Installed[/green] {engine} {tag}")


@core_app.command("update")
def update_engine(
    engine: str = typer.Argument(..., help="xray, singbox or aether"),
    pre: bool = typer.Option(False, "--pre", help=_PRE_HELP),
    variant: str | None = typer.Option(None, "--variant", help=_VARIANT_HELP),
) -> None:
    """Install the latest release if it's newer than what's currently active (never downgrades)."""
    _check_engine(engine)
    chosen = _check_variant(engine, variant)
    current = installer.current_version(engine)
    console.print(f"Checking latest {engine} {'release (pre-releases included)' if pre else 'stable release'}...")
    try:
        release = installer.fetch_release_for(engine, None, pre)
    except DownloadError as exc:
        raise V2rmError(str(exc)) from exc
    tag = release.tag

    if tag == current:
        console.print(f"[dim]{engine} is already up to date ({tag}).[/dim]")
        return
    if current and compare_versions(tag, current) < 0:
        console.print(f"[dim]{engine} {current} is newer than the latest {'release' if pre else 'stable release'} ({tag}); nothing to do.[/dim]")
        if not pre:
            console.print("[dim]Add --pre to include pre-releases.[/dim]")
        return

    try:
        installer.install_engine(engine, release, progress=console.print, variant=chosen)
    except DownloadError as exc:
        raise V2rmError(str(exc)) from exc
    console.print(f"[green]Updated[/green] {engine} {current or '(none)'} -> {tag}")


@core_app.command("use")
def use_engine(engine: str = typer.Argument(..., help="xray or singbox")) -> None:
    """Set the default engine for new connections."""
    _check_engine(engine)
    if engine not in _DEFAULT_ENGINES:
        raise V2rmError(
            f"'{engine}' can't be the default engine: it only runs Aether profiles "
            f"(`v2rm add aether`). Choose one of: {', '.join(_DEFAULT_ENGINES)}"
        )
    state_store = AppStateStore()
    state = state_store.load()
    state.active_engine = EngineKind(engine)
    state_store.save(state)
    console.print(f"[green]Active engine set to[/green] {engine}")


@core_app.command("remove")
def remove_engine(
    engine: str = typer.Argument(..., help="xray, singbox or aether"),
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
