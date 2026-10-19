"""A Typer group whose first argument may be a *value* rather than a subcommand.

`v2rm add masque --server ...` needs `add` to be a group, while
`v2rm add trojan://...`, `v2rm add -`, `v2rm add -f FILE` and `v2rm add --json
FILE` have to keep working exactly as before. When the first argument isn't
one of the group's subcommands, everything is handed to the default one.
Only the long-stable `resolve_command`/`parse_args` hooks are overridden.
"""

from __future__ import annotations

from typing import Any

from typer.core import TyperGroup


class DefaultCommandGroup(TyperGroup):
    default_command_name = "link"

    def parse_args(self, ctx: Any, args: list[str]) -> Any:
        if not args:
            args = [self.default_command_name]  # bare `v2rm add`: let the default command explain itself
        return super().parse_args(ctx, args)

    def resolve_command(self, ctx: Any, args: list[str]) -> Any:
        if args and args[0] not in self.commands:
            args = [self.default_command_name, *args]
        return super().resolve_command(ctx, args)
