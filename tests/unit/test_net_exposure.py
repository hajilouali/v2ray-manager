from __future__ import annotations

import pytest

from v2rm.net.exposure import listen_warning, open_proxy_warning, suggested_source, ufw_commands


def test_no_warning_for_loopback():
    assert listen_warning("127.0.0.1") is None
    assert listen_warning("::1") is None
    assert open_proxy_warning("127.0.0.1", 10808, 10809) == []


def test_one_line_warning_for_a_wildcard():
    text = listen_warning("0.0.0.0")
    assert text is not None and "\n" not in text
    assert "all interfaces" in text and "not just localhost" in text


def test_one_line_warning_for_a_specific_address_names_it():
    text = listen_warning("172.17.0.1")
    assert text is not None and "\n" not in text
    assert "172.17.0.1" in text and "not just localhost" in text


@pytest.mark.parametrize(
    ("listen", "expected"),
    [
        ("0.0.0.0", "172.16.0.0/12"),
        ("::", "172.16.0.0/12"),
        ("172.17.0.1", "172.16.0.0/12"),
        ("172.31.255.1", "172.16.0.0/12"),
        ("172.32.0.1", "<trusted-subnet>"),  # just outside 172.16.0.0/12
        ("192.168.1.5", "<trusted-subnet>"),
        ("10.0.0.2", "<trusted-subnet>"),
    ],
)
def test_suggested_firewall_source(listen, expected):
    assert suggested_source(listen) == expected


def test_ufw_commands_for_the_docker_case():
    assert ufw_commands("172.17.0.1", 10808, 10809) == [
        "sudo ufw allow from 172.16.0.0/12 to any port 10808,10809 proto tcp",
        "sudo ufw deny 10808,10809/tcp",
    ]


def test_ufw_commands_follow_the_configured_ports():
    allow, deny = ufw_commands("0.0.0.0", 1080, 8080)
    assert "port 1080,8080 proto tcp" in allow and deny.endswith("1080,8080/tcp")


def test_open_proxy_warning_says_it_is_open_and_how_to_close_it():
    lines = open_proxy_warning("0.0.0.0", 10808, 10809)
    text = "\n".join(lines)
    assert "no authentication" in lines[0]
    assert "10808/10809" in lines[0] and "every interface" in lines[0]
    assert "sudo ufw allow from 172.16.0.0/12 to any port 10808,10809 proto tcp" in text
    assert "v2rm port set --auth USER:PASS" in text


def test_open_proxy_warning_names_a_specific_address():
    assert "172.17.0.1" in open_proxy_warning("172.17.0.1", 10808, 10809)[0]
