from __future__ import annotations

import subprocess

import pytest

from v2rm.errors import V2rmError
from v2rm.net.docker import (
    OTHER_NETWORKS_NOTE,
    parse_gateway_output,
    parse_interface_address,
    resolve_docker_gateway,
)

DOCKER0 = "5: docker0    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0\\       valid_lft forever preferred_lft forever\n"


class ScriptedRunner:
    """Answers by command: a dict of first-word -> (returncode, stdout) or an exception."""

    def __init__(self, **answers):
        self.answers = answers
        self.calls: list[list[str]] = []

    def __call__(self, args, **kwargs):
        self.calls.append(args)
        answer = self.answers[args[0]]
        if isinstance(answer, Exception):
            raise answer
        returncode, stdout = answer
        return subprocess.CompletedProcess(args, returncode, stdout, "")


def test_gateway_output_parsing():
    assert parse_gateway_output("172.17.0.1\n") == "172.17.0.1"
    assert parse_gateway_output("  10.88.0.1  ") == "10.88.0.1"
    assert parse_gateway_output("<no value>") is None
    assert parse_gateway_output("") is None
    assert parse_gateway_output("Error: No such network") is None


def test_interface_address_parsing():
    assert parse_interface_address(DOCKER0) == "172.17.0.1"
    assert parse_interface_address("5: docker0    inet6 fe80::1/64 scope link") is None
    assert parse_interface_address("") is None


def test_docker_inspect_is_asked_exactly_as_documented_and_preferred():
    runner = ScriptedRunner(docker=(0, "172.17.0.1\n"), ip=(0, DOCKER0))
    gateway = resolve_docker_gateway(runner)
    assert gateway.address == "172.17.0.1"
    assert "docker network inspect bridge" in gateway.source
    assert runner.calls == [["docker", "network", "inspect", "bridge", "--format", "{{(index .IPAM.Config 0).Gateway}}"]]


def test_a_custom_bridge_gateway_is_returned_as_is():
    assert resolve_docker_gateway(ScriptedRunner(docker=(0, "192.168.200.1\n"))).address == "192.168.200.1"


@pytest.mark.parametrize(
    "docker_answer",
    [(1, ""), (0, "<no value>"), (0, ""), PermissionError("docker.sock"), FileNotFoundError("docker"),
     subprocess.TimeoutExpired("docker", 10)],
    ids=["failed", "no-value", "empty", "permission", "no-docker", "timeout"],
)
def test_falls_back_to_the_docker0_interface(docker_answer):
    runner = ScriptedRunner(docker=docker_answer, ip=(0, DOCKER0))
    gateway = resolve_docker_gateway(runner)
    assert gateway.address == "172.17.0.1"
    assert "docker0" in gateway.source
    assert runner.calls[1] == ["ip", "-4", "-o", "addr", "show", "dev", "docker0"]


def test_failing_both_ways_says_what_to_do():
    runner = ScriptedRunner(docker=FileNotFoundError("docker"), ip=(1, ""))
    with pytest.raises(V2rmError) as err:
        resolve_docker_gateway(runner)
    assert "v2rm port set --listen 172.17.0.1" in str(err.value)


def test_the_other_networks_note_does_not_overclaim():
    # Binding a bridge address does not, by itself, stop containers on other
    # networks from reaching it (the firewall decides); the note must say what
    # to check, not assert that they can't.
    assert "cannot reach" not in OTHER_NETWORKS_NOTE and "can't reach" not in OTHER_NETWORKS_NOTE
    assert "firewall" in OTHER_NETWORKS_NOTE and "0.0.0.0" in OTHER_NETWORKS_NOTE
