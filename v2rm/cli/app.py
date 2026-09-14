from __future__ import annotations

import sys

import typer
from rich.console import Console

from v2rm import __version__
from v2rm.cli.add import add_command
from v2rm.cli.backup import export_command, import_command
from v2rm.cli.connect import connect_command, disconnect_command, status_command
from v2rm.cli.core import core_app
from v2rm.cli.doctor import doctor_command
from v2rm.cli.env import env_command, exec_command
from v2rm.cli.port import port_app
from v2rm.cli.profile import profile_app
from v2rm.cli.route import route_app
from v2rm.cli.sub import sub_app
from v2rm.cli.test import test_command
from v2rm.errors import V2rmError
from v2rm.store import paths

console = Console()
err_console = Console(stderr=True)

app = typer.Typer(
    name="v2rm",
    help="A friendly CLI manager for Xray-core and sing-box on Linux.",
    add_completion=True,
    no_args_is_help=False,
)
app.command(name="add")(add_command)
app.command(name="connect")(connect_command)
app.command(name="disconnect")(disconnect_command)
app.command(name="status")(status_command)
app.command(name="test")(test_command)
app.command(name="env")(env_command)
app.command(name="exec", context_settings={"ignore_unknown_options": True})(exec_command)
app.command(name="export")(export_command)
app.command(name="import")(import_command)
app.command(name="doctor")(doctor_command)
app.add_typer(profile_app, name="profile")
app.add_typer(core_app, name="core")
app.add_typer(sub_app, name="sub")
app.add_typer(route_app, name="route")
app.add_typer(port_app, name="port")


@app.callback(invoke_without_command=True)
def _root(ctx: typer.Context) -> None:
    if ctx.invoked_subcommand is None:
        console.print(ctx.get_help())
        raise typer.Exit()


@app.command()
def version() -> None:
    """Show the v2rm version and installed engine versions."""
    from v2rm.coredl.install import current_version

    console.print(f"v2rm [bold]{__version__}[/bold]")
    for engine in ("xray", "singbox"):
        v = current_version(engine)
        console.print(f"  {engine:<8} {v if v else '[dim]not installed[/dim]'}")


def main() -> None:
    paths.ensure_dirs()
    verbose = "-v" in sys.argv or "--verbose" in sys.argv
    try:
        app()
    except V2rmError as exc:
        if verbose:
            raise
        err_console.print(f"[bold red]Error:[/bold red] {exc}")
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
