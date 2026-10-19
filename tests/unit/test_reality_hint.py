"""Real Xray 26.10.17 says `invalid "password"` for a bad REALITY client key, even when the config
said `publicKey` (found by running the integration tests on a real server)."""

from __future__ import annotations

import pytest

from v2rm.engines.xray.generate import needs_preflight
from v2rm.parsers import parse_link
from v2rm.process.preflight import explain_xray_failure

REAL_XRAY_OUTPUT = (
    "Xray 26.10.17 (Xray, Penetrates Everything.) 92ccc93 (go1.27.2 linux/amd64)\n"
    "A unified platform for anti-censorship.\n"
    "Failed to start: main: failed to load config files: [/tmp/config.json] > infra/conf: failed to build outbound "
    "config with tag proxy > infra/conf: failed to build stream settings for outbound detour > infra/conf: "
    'Failed to build REALITY config. > infra/conf: invalid "password": cmV2ZXJzZS1zdGFuZGlu-bm90LWEtcmVhbC1rZXktMTIzNDU2'
)


def test_the_real_error_gets_a_hint_that_explains_the_key_format():
    message = explain_xray_failure(REAL_XRAY_OUTPUT)
    assert 'invalid "password"' in message  # Xray's own words stay
    assert "Hint: The REALITY public key" in message
    assert "base64url" in message and "32 bytes" in message and "pbk" in message


@pytest.mark.parametrize(
    "output",
    [
        'infra/conf: invalid "password": abc',  # not about REALITY (e.g. a shadowsocks/MASQUE password)
        "Failed to build REALITY config. > infra/conf: empty serverName",
    ],
)
def test_other_failures_do_not_get_the_reality_key_hint(output):
    assert "REALITY public key" not in explain_xray_failure(output)


def test_reality_profiles_are_validated_before_they_are_started():
    link = "vless://11111111-2222-3333-4444-555555555555@r.example.com:443?security=reality&sni=h.example.com&pbk=k&sid=ab#r"
    assert needs_preflight(parse_link(link))
    assert not needs_preflight(parse_link("vless://11111111-2222-3333-4444-555555555555@v.example.com:443?security=tls#t"))
