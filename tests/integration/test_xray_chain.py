"""Chained hops and the Aether front against the real Xray (see conftest.py to enable).

Two kinds of test:

* `xray run -test` on the configs v2rm generates for a hop that dials through the previous one
  and for the front: does the real Xray accept them?
* a real chain on loopback, nothing leaving the machine: Xray as a "server" (a Trojan inbound),
  Xray as the previous hop (a plain SOCKS proxy, standing in for Aether's), and the config v2rm
  generates for the next hop. A request through it must reach its target, and the previous hop
  must have seen the connection to the server -- proof that `dialerProxy` really sends the hop's
  own connection through it, which no unit test can show.
"""

from __future__ import annotations

import base64
import json
import os
import socket
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
import requests

from v2rm.engines.xray.generate import generate_config, generate_front_config
from v2rm.errors import ConfigTestError
from v2rm.models.auth import ProxyAuth
from v2rm.models.enums import Protocol
from v2rm.models.profile import Profile
from v2rm.net.ports import free_port
from v2rm.net.proxy_url import ProxyEndpoint, parse_proxy_url
from v2rm.parsers import parse_link
from v2rm.process.preflight import run_config_test
from v2rm.routing.presets import GLOBAL

pytestmark = pytest.mark.integration

REALITY_PUBLIC_KEY = base64.urlsafe_b64encode(bytes(range(32))).rstrip(b"=").decode()
UPSTREAMS = {
    "socks": ProxyEndpoint("socks5", "127.0.0.1", 41000),
    "socks-login": parse_proxy_url("socks5://alice:s3cret@127.0.0.1:41000"),
    "http": ProxyEndpoint("http", "127.0.0.1", 41001),
}


def check(xray_binary, assets_dir, tmp_path, config) -> None:
    path = tmp_path / "config.json"
    path.write_text(json.dumps(config), encoding="utf-8")
    try:
        run_config_test(xray_binary, path, assets_dir)
    except ConfigTestError as exc:
        pytest.fail(str(exc))


# ---- does the real Xray accept what v2rm generates? ---------------------------------------------------------


@pytest.mark.parametrize("upstream", list(UPSTREAMS), ids=list(UPSTREAMS))
@pytest.mark.parametrize(
    "link",
    [
        "trojan://pw@t.example.com:443?security=tls&sni=t.example.com#trojan",
        "trojan://pw@t.example.com:443#trojan-plain",
        "vless://11111111-2222-3333-4444-555555555555@v.example.com:443?security=tls&sni=v.example.com&type=ws&path=%2Fws#vless-ws",
        f"vless://11111111-2222-3333-4444-555555555555@r.example.com:443?security=reality&sni=hide.example.com&pbk={REALITY_PUBLIC_KEY}&sid=ab&fp=chrome&flow=xtls-rprx-vision#reality",
        "ss://YWVzLTEyOC1nY206cGFzc3dvcmQ@s.example.com:8388#ss",
        "masque://m.example.com:443?sni=m.example.com&alpn=h2#masque",
    ],
    ids=["trojan-tls", "trojan-plain", "vless-ws", "vless-reality", "shadowsocks", "masque-h2"],
)
def test_a_hop_dialled_through_another_is_accepted(xray_binary, assets_dir, tmp_path, link, upstream):
    config = generate_config(parse_link(link), GLOBAL, 10808, 10809, upstream=UPSTREAMS[upstream])
    check(xray_binary, assets_dir, tmp_path, config)


@pytest.mark.parametrize("listen", ["127.0.0.1", "0.0.0.0", "172.18.0.1"])
@pytest.mark.parametrize("auth", [None, ProxyAuth("user", "p@ss:word")], ids=["no-login", "login"])
def test_the_front_is_accepted(xray_binary, assets_dir, tmp_path, listen, auth):
    config = generate_front_config(
        GLOBAL, 10808, 10809, ProxyEndpoint("socks5", "127.0.0.1", 41000), listen_address=listen, auth=auth
    )
    check(xray_binary, assets_dir, tmp_path, config)


# ---- a real chain on loopback ---------------------------------------------------------------------------------


class Hello(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        body = b"hello from the target"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


@pytest.fixture
def target():
    server = ThreadingHTTPServer(("127.0.0.1", 0), Hello)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield server.server_address[1]
    server.shutdown()


@pytest.fixture
def run_xray(xray_binary, assets_dir, tmp_path):
    started: list[subprocess.Popen] = []

    def start(name: str, config: dict, port: int) -> None:
        path = tmp_path / f"{name}.json"
        path.write_text(json.dumps(config), encoding="utf-8")
        env = dict(os.environ, XRAY_LOCATION_ASSET=str(assets_dir))
        proc = subprocess.Popen(
            [str(xray_binary), "run", "-c", str(path)], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT
        )
        started.append(proc)
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                pytest.fail(f"xray ({name}) exited with code {proc.returncode}")
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.3):
                    return
            except OSError:
                time.sleep(0.1)
        pytest.fail(f"xray ({name}) never listened on {port}")

    yield start
    for proc in started:
        proc.terminate()
    for proc in started:
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


def socks_get(port: int, url: str, auth: ProxyAuth | None = None) -> requests.Response:
    userinfo = f"{auth.userinfo()}@" if auth else ""
    proxy = f"socks5h://{userinfo}127.0.0.1:{port}"
    return requests.get(url, proxies={"http": proxy, "https": proxy}, timeout=10)


def trojan_server(port: int) -> dict:
    # A server-side freedom outbound refuses private addresses by default (Xray's own safety
    # net), and this target is on loopback: allow it explicitly.
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {"listen": "127.0.0.1", "port": port, "protocol": "trojan", "settings": {"clients": [{"password": "pw"}]}}
        ],
        "outbounds": [{"protocol": "freedom", "settings": {"finalRules": [{"action": "allow"}]}}],
    }


def plain_socks_hop(port: int, access_log) -> dict:
    """The previous hop: a SOCKS proxy that dials directly, logging what it is asked to reach
    (it stands in for Aether's SOCKS5 port)."""
    return {
        "log": {"loglevel": "info", "access": str(access_log)},
        "inbounds": [
            {"tag": "socks-in", "listen": "127.0.0.1", "port": port, "protocol": "socks", "settings": {"auth": "noauth", "udp": True}}
        ],
        "outbounds": [{"protocol": "freedom", "settings": {}}],
    }


def test_a_chained_hop_really_leaves_through_the_previous_hop(run_xray, target, tmp_path):
    server_port, hop_port, user_port = free_port(), free_port(), free_port()
    access = tmp_path / "hop-access.log"
    run_xray("server", trojan_server(server_port), server_port)
    run_xray("previous-hop", plain_socks_hop(hop_port, access), hop_port)

    profile = Profile(name="t", protocol=Protocol.TROJAN, server="127.0.0.1", port=server_port, password="pw")
    config = generate_config(
        profile, GLOBAL, user_port, free_port(), upstream=ProxyEndpoint("socks5", "127.0.0.1", hop_port)
    )
    run_xray("chained", config, user_port)

    response = socks_get(user_port, f"http://127.0.0.1:{target}/")
    assert response.status_code == 200 and response.text == "hello from the target"

    time.sleep(0.5)
    seen = access.read_text(encoding="utf-8", errors="replace")
    # The previous hop was asked to reach the *server* -- the chained hop's own connection went through it.
    assert f"127.0.0.1:{server_port}" in seen, seen


def test_without_the_dialer_proxy_the_previous_hop_sees_nothing(run_xray, target, tmp_path):
    """The control: the same request without a chain never touches the hop."""
    server_port, hop_port, user_port = free_port(), free_port(), free_port()
    access = tmp_path / "hop-access.log"
    run_xray("server", trojan_server(server_port), server_port)
    run_xray("previous-hop", plain_socks_hop(hop_port, access), hop_port)

    profile = Profile(name="t", protocol=Protocol.TROJAN, server="127.0.0.1", port=server_port, password="pw")
    run_xray("direct", generate_config(profile, GLOBAL, user_port, free_port()), user_port)

    assert socks_get(user_port, f"http://127.0.0.1:{target}/").status_code == 200
    time.sleep(0.5)
    assert not access.exists() or f"127.0.0.1:{server_port}" not in access.read_text(encoding="utf-8", errors="replace")


def test_the_front_enforces_its_login_in_front_of_a_proxy_without_one(run_xray, target, tmp_path):
    hop_port, front_port = free_port(), free_port()
    run_xray("backend", plain_socks_hop(hop_port, tmp_path / "backend.log"), hop_port)

    login = ProxyAuth("user", "p@ss:word")
    front = generate_front_config(
        GLOBAL, front_port, free_port(), ProxyEndpoint("socks5", "127.0.0.1", hop_port), auth=login
    )
    run_xray("front", front, front_port)

    ok = socks_get(front_port, f"http://127.0.0.1:{target}/", auth=login)
    assert ok.status_code == 200 and ok.text == "hello from the target"
    with pytest.raises(requests.exceptions.RequestException):
        socks_get(front_port, f"http://127.0.0.1:{target}/")  # no login
    with pytest.raises(requests.exceptions.RequestException):
        socks_get(front_port, f"http://127.0.0.1:{target}/", auth=ProxyAuth("user", "wrong"))
