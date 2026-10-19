from __future__ import annotations

import pytest

from v2rm.errors import ParseError, ProfileValidationError
from v2rm.models.enums import Protocol, SecurityKind
from v2rm.models.profile import Profile, TlsSettings, TransportSettings
from v2rm.parsers import SUPPORTED_SCHEMES, parse_link, to_link
from v2rm.parsers.masque import validate_masque


def test_masque_scheme_is_registered():
    assert "masque" in SUPPORTED_SCHEMES


def test_parse_basic_masque_link_defaults_to_http2_mode():
    p = parse_link("masque://alice:s3cret@m.example.com:443?sni=front.example.com&path=%2Fmasque#My%20Masque")
    assert p.protocol == Protocol.MASQUE
    assert p.name == "My Masque"
    assert p.server == "m.example.com" and p.port == 443
    assert p.extra["user"] == "alice"
    assert p.password == "s3cret"
    assert p.tls.security == SecurityKind.TLS
    assert p.tls.sni == "front.example.com"
    assert p.tls.alpn == ["h2"]  # HTTP/2 mode is the default
    assert p.transport.path == "/masque"


def test_masque_link_without_credentials():
    p = parse_link("masque://m.example.com:8443?sni=m.example.com")
    assert "user" not in p.extra
    assert p.password == ""
    assert p.name == "m.example.com:8443"


def test_explicit_alpn_is_respected():
    p = parse_link("masque://m.example.com:443?alpn=h3,h2")
    assert p.tls.alpn == ["h3", "h2"]


def test_masque_round_trip_with_every_option():
    link = (
        "masque://alice:pw%3A1@m.example.com:443?sni=front.example.com&alpn=h2&fp=chrome&path=%2Fmasque"
        "&host=h.example.com&headers=%7B%22X-Token%22%3A%22abc%22%7D"
        "&fm=%7B%22tcp%22%3A%5B%7B%22type%22%3A%22fragment%22%7D%5D%7D&dns=1.1.1.1,8.8.8.8#name"
    )
    p1 = parse_link(link)
    assert p1.password == "pw:1"
    assert p1.transport.headers == {"X-Token": "abc"}
    assert p1.transport.finalmask == {"tcp": [{"type": "fragment"}]}
    assert p1.extra["remote_dns"] == ["1.1.1.1", "8.8.8.8"]

    p2 = parse_link(to_link(p1))
    assert p2.identity_key() == p1.identity_key()
    assert p2.password == p1.password
    assert p2.extra == p1.extra
    assert p2.tls.alpn == p1.tls.alpn
    assert p2.tls.fingerprint == "chrome"
    assert p2.transport.headers == p1.transport.headers
    assert p2.transport.finalmask == p1.transport.finalmask
    assert p2.transport.host == "h.example.com"


def test_masque_round_trip_with_warp():
    warp = '{"privateKey":"PRIV","publicKey":"PUB","address":["172.16.0.2/32"]}'
    link = "masque://m.example.com:443?sni=m.example.com&warp=" + warp.replace('"', "%22").replace("{", "%7B").replace("}", "%7D")
    p1 = parse_link(link)
    assert p1.extra["warp"]["privateKey"] == "PRIV"
    p2 = parse_link(to_link(p1))
    assert p2.extra["warp"] == p1.extra["warp"]


def test_masque_identity_key_is_server_port_user_sni_path():
    a = parse_link("masque://u:p@m.example.com:443?sni=s&path=%2Fx#one")
    b = parse_link("masque://u:other-password@m.example.com:443?sni=s&path=%2Fx#two")
    c = parse_link("masque://v:p@m.example.com:443?sni=s&path=%2Fx#one")
    assert a.identity_key() == b.identity_key()  # password and name aren't part of the identity
    assert a.identity_key() != c.identity_key()


def test_user_pass_together_with_warp_is_rejected():
    warp = "%7B%22privateKey%22%3A%22a%22%2C%22publicKey%22%3A%22b%22%2C%22address%22%3A%5B%22172.16.0.2%2F32%22%5D%7D"
    with pytest.raises(ParseError, match="warp"):
        parse_link("masque://u:p@m.example.com:443?warp=" + warp)


def test_incomplete_warp_block_is_rejected():
    with pytest.raises(ParseError, match="warp"):
        parse_link("masque://m.example.com:443?warp=%7B%22privateKey%22%3A%22a%22%7D")


def test_path_must_start_with_a_slash():
    with pytest.raises(ParseError, match="path"):
        parse_link("masque://m.example.com:443?path=masque")


def test_forbidden_headers_are_rejected():
    with pytest.raises(ParseError, match="Host"):
        parse_link("masque://m.example.com:443?headers=%7B%22Host%22%3A%22x%22%7D")
    with pytest.raises(ParseError, match="Authorization"):
        parse_link("masque://u:p@m.example.com:443?headers=%7B%22Authorization%22%3A%22x%22%7D")


def test_authorization_header_is_fine_without_user_pass():
    p = parse_link("masque://m.example.com:443?headers=%7B%22Authorization%22%3A%22Bearer%20x%22%7D")
    assert p.transport.headers == {"Authorization": "Bearer x"}


def test_remote_dns_must_be_ip_addresses():
    with pytest.raises(ParseError, match="remote DNS"):
        parse_link("masque://m.example.com:443?dns=dns.example.com")


def test_user_containing_a_colon_is_invalid():
    p = Profile(
        name="m", protocol=Protocol.MASQUE, server="m.example.com", port=443,
        tls=TlsSettings(security=SecurityKind.TLS, alpn=["h2"]),
        transport=TransportSettings(), extra={"user": "a:b"},
    )
    with pytest.raises(ProfileValidationError, match='":"'):
        validate_masque(p)


def test_missing_server_or_bad_port_is_invalid():
    base = dict(name="m", protocol=Protocol.MASQUE, tls=TlsSettings(security=SecurityKind.TLS, alpn=["h2"]))
    with pytest.raises(ProfileValidationError):
        validate_masque(Profile(server="", port=443, **base))
    with pytest.raises(ProfileValidationError):
        validate_masque(Profile(server="m.example.com", port=70000, **base))


# ---- the extra checks Xray-core's MasqueConfig.Build makes (read from its source) --------------------------


def masque_profile(**transport) -> Profile:
    return Profile(
        name="m", protocol=Protocol.MASQUE, server="m.example.com", port=443,
        tls=TlsSettings(security=SecurityKind.TLS, alpn=["h2"]),
        transport=TransportSettings(**transport),
    )


@pytest.mark.parametrize("path", ["/masque", "/", "/masque/{target}", "/{target}/{ipproto}", "/connect?t={target}&p={ipproto}"])
def test_paths_may_use_the_two_template_variables(path):
    validate_masque(masque_profile(path=path))


@pytest.mark.parametrize("path", ["/{other}", "/a{b", "/a}b", "/{target}{"])
def test_any_other_braces_in_the_path_are_rejected(path):
    with pytest.raises(ProfileValidationError, match="only the variables"):
        validate_masque(masque_profile(path=path))


@pytest.mark.parametrize("host", ["h.example.com", "h.example.com:8443", "[2001:db8::1]:443", "10.0.0.1"])
def test_plain_hosts_are_fine(host):
    validate_masque(masque_profile(host=host))


@pytest.mark.parametrize("host", ["h.example.com/path", "h.example.com?x=1", "u@h.example.com", "h example.com", "h.example.com#f"])
def test_a_host_that_is_not_a_bare_authority_is_rejected(host):
    with pytest.raises(ProfileValidationError, match='invalid "host"'):
        validate_masque(masque_profile(host=host))


@pytest.mark.parametrize("name", ["X-Token", "x_custom.header", "Accept", "X-1"])
def test_ordinary_header_names_are_fine(name):
    validate_masque(masque_profile(headers={name: "v"}))


@pytest.mark.parametrize(("name", "value"), [("Bad Name", "v"), ("X:Y", "v"), ("", "v"), ("X-A", "line1\r\nInjected: 1"), ("X-A", "nul\x00")])
def test_invalid_header_names_or_values_are_rejected(name, value):
    with pytest.raises(ProfileValidationError, match="invalid header"):
        validate_masque(masque_profile(headers={name: value}))


def test_a_password_without_a_user_is_not_rejected_because_xray_does_not_reject_it():
    p = masque_profile()
    p.password = "only-a-pass"
    validate_masque(p)
