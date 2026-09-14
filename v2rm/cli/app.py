from __future__ import annotations

import sys

import typer
from rich.console import Console

from v2rm import __version__
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


@app.callback(invoke_without_command=True)
def _root(ctx: typer.Context) -> None:
    if ctx.invoked_subcommand is None:
        console.print(ctx.get_help())
        raise typer.Exit()


@app.command()
def version() -> None:
    """Show the v2rm version."""
    console.print(f"v2rm [bold]{__version__}[/bold]")


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
