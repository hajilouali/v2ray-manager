from __future__ import annotations

import subprocess

import pytest

from v2rm.errors import V2rmError
from v2rm.net.addresses import (
    check_listen_address,
    is_loopback,
    is_wildcard,
    local_address_exists,
    local_addresses,
    parse_ip,
    reaches_beyond_localhost,
)

IP_ADDR_OUTPUT = """\
1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever preferred_lft forever
1: lo    inet6 ::1/128 scope host \\       valid_lft forever preferred_lft forever
2: eth0    inet 192.168.1.5/24 brd 192.168.1.255 scope global dynamic eth0\\       valid_lft 86000sec preferred_lft 86000sec
2: eth0    inet6 fe80::1c2b:3dff:fe4e:5f60/64 scope link \\       valid_lft forever preferred_lft forever
3: docker0    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0\\       valid_lft forever preferred_lft forever
"""


def fake_run(returncode=0, stdout="", raises=None):
    def run(args, **kwargs):
        if raises:
            raise raises
        return subprocess.CompletedProcess(args, returncode, stdout, "")

    return run


@pytest.mark.parametrize("address", ["127.0.0.1", "127.1.2.3", "::1"])
def test_loopback(address):
    assert is_loopback(address)
    assert not reaches_beyond_localhost(address)


@pytest.mark.parametrize("address", ["0.0.0.0", "::", "172.17.0.1", "192.168.1.5", "junk", ""])
def test_not_loopback(address):
    assert not is_loopback(address)
    assert reaches_beyond_localhost(address)


def test_wildcards():
    assert is_wildcard("0.0.0.0") and is_wildcard("::") and is_wildcard(" 0.0.0.0 ")
    assert not is_wildcard("127.0.0.1") and not is_wildcard("172.17.0.1")


def test_parse_ip():
    assert str(parse_ip(" 10.0.0.1 ")) == "10.0.0.1"
    assert parse_ip("not-an-ip") is None
    assert parse_ip("10.0.0") is None


def test_this_host_has_loopback_but_not_a_documentation_address():
    assert local_address_exists("127.0.0.1")
    assert local_address_exists("0.0.0.0")
    assert local_address_exists("::")
    assert not local_address_exists("203.0.113.77")  # TEST-NET-3: never assigned to a real interface
    assert not local_address_exists("not-an-ip")


def test_local_addresses_are_read_from_ip_addr():
    found = local_addresses(fake_run(stdout=IP_ADDR_OUTPUT))
    assert found == ["127.0.0.1", "::1", "192.168.1.5", "fe80::1c2b:3dff:fe4e:5f60", "172.17.0.1"]


@pytest.mark.parametrize(
    "runner",
    [fake_run(returncode=1), fake_run(raises=FileNotFoundError("ip")), fake_run(raises=subprocess.TimeoutExpired("ip", 5)),
     fake_run(stdout="")],
    ids=["failure", "missing", "timeout", "empty"],
)
def test_local_addresses_is_none_when_it_cannot_be_determined(runner):
    assert local_addresses(runner) is None


def test_check_rejects_something_that_is_not_an_ip():
    with pytest.raises(V2rmError, match="valid IP address"):
        check_listen_address("not-an-ip")


def test_check_passes_wildcards_without_probing():
    def must_not_probe(address):
        raise AssertionError("wildcards always pass")

    check_listen_address("0.0.0.0", exists=must_not_probe)
    check_listen_address("::", exists=must_not_probe)


def test_check_passes_an_address_the_host_has():
    check_listen_address("172.17.0.1", exists=lambda a: True)


def test_check_rejects_an_address_the_host_does_not_have_and_helps():
    with pytest.raises(V2rmError) as err:
        check_listen_address("172.17.0.1", exists=lambda a: False, lister=lambda: ["127.0.0.1", "192.168.1.5"])
    message = str(err.value)
    assert "no address 172.17.0.1" in message
    assert "Its addresses: 127.0.0.1, 192.168.1.5." in message
    assert "v2rm port set --listen docker" in message


def test_check_still_rejects_when_the_address_list_is_unavailable():
    with pytest.raises(V2rmError) as err:
        check_listen_address("172.17.0.1", exists=lambda a: False, lister=lambda: None)
    assert "Its addresses" not in str(err.value)
