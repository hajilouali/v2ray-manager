from __future__ import annotations

import typer
from typer.testing import CliRunner

from v2rm.cli.groups import DefaultCommandGroup

runner = CliRunner()

toy = typer.Typer()
inner = typer.Typer(cls=DefaultCommandGroup, context_settings={"ignore_unknown_options": True})


@inner.command("link")
def link_command(value: str | None = typer.Argument(None), flag: str | None = typer.Option(None, "--flag")) -> None:
    typer.echo(f"link value={value} flag={flag}")


@inner.command("special")
def special_command(count: int = typer.Option(1, "--count")) -> None:
    typer.echo(f"special count={count}")


toy.add_typer(inner, name="add")


@toy.command("other")
def other_command() -> None:
    typer.echo("other")


def test_a_subcommand_name_runs_that_subcommand():
    result = runner.invoke(toy, ["add", "special", "--count", "3"])
    assert result.exit_code == 0, result.output
    assert result.stdout.strip() == "special count=3"


def test_anything_else_goes_to_the_default_command():
    for args, expected in (
        (["add", "some-value"], "link value=some-value flag=None"),
        (["add", "-"], "link value=- flag=None"),
        (["add", "trojan://pw@h:1#x"], "link value=trojan://pw@h:1#x flag=None"),
        (["add", "--flag", "f"], "link value=None flag=f"),
        (["add", "--flag", "f", "v"], "link value=v flag=f"),
        (["add", "v", "--flag", "f"], "link value=v flag=f"),
        (["add"], "link value=None flag=None"),
    ):
        result = runner.invoke(toy, args)
        assert result.exit_code == 0, (args, result.output)
        assert result.stdout.strip() == expected, args


def test_the_default_command_can_still_be_named():
    assert runner.invoke(toy, ["add", "link", "v"]).stdout.strip() == "link value=v flag=None"


def test_an_unknown_option_is_reported_by_the_default_command():
    result = runner.invoke(toy, ["add", "--bogus"])
    assert result.exit_code == 2
    assert "--bogus" in result.output


def test_group_help_lists_the_subcommands():
    result = runner.invoke(toy, ["add", "--help"])
    assert result.exit_code == 0
    assert "link" in result.output and "special" in result.output


def test_other_commands_are_unaffected():
    assert runner.invoke(toy, ["other"]).stdout.strip() == "other"
