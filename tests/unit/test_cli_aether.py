"""`v2rm aether register | gateways | env`, and what `doctor` says about Aether."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
from typer.testing import CliRunner

from v2rm.cli.app import app
from v2rm.engines.aether.files import config_path, derive_sibling
from v2rm.errors import EngineNotInstalledError
from v2rm.models.aether import AetherMode, AetherSettings
from v2rm.models.enums import Protocol
from v2rm.models.profile import Profile
from v2rm.process import supervisor
from v2rm.store import paths
from v2rm.store.profiles import ProfileStore

runner = CliRunner()


def add_aether(name="WARP", **settings) -> Profile:
    return ProfileStore().add(Profile(name=name, protocol=Protocol.AETHER, aether=AetherSettings(**settings)))


def add_trojan() -> Profile:
    return ProfileStore().add(
        Profile(name="trojan", protocol=Protocol.TROJAN, server="t.example.com", port=443, password="pw")
    )


@pytest.fixture
def aether_installed(monkeypatch, tmp_path):
    binary = tmp_path / "aether"
    monkeypatch.setattr(supervisor, "_binary_path", lambda engine: binary)
    return binary


# ---- register -----------------------------------------------------------------------------------------


class FakeRun:
    """Stands in for running `aether` with AETHER_REGISTER set."""

    def __init__(self, returncode=0, output=None, creates=True, timeout=False):
        self.returncode, self.creates, self.timeout = returncode, creates, timeout
        self.output = output if output is not None else (
            "[2026-10-20T10:00:00.000Z INFO  aether] [+] provisioned and saved new warp identity\n"
            "[2026-10-20T10:00:01.000Z INFO  aether] [+] identities ready: masque\n"
        )
        self.calls: list[dict] = []

    def __call__(self, argv, **kwargs):
        self.calls.append({"argv": argv, **kwargs})
        if self.timeout:
            raise subprocess.TimeoutExpired(argv, kwargs["timeout"])
        if self.creates and self.returncode == 0:
            base = Path(kwargs["env"]["AETHER_CONFIG"])
            derive_sibling(base, "masque").write_text("keys")
        return subprocess.CompletedProcess(argv, self.returncode, stdout=self.output)


def test_register_runs_aether_with_the_profiles_settings_and_register_request(monkeypatch, aether_installed):
    fake = FakeRun()
    monkeypatch.setattr("v2rm.cli.aether.subprocess.run", fake)
    warp = add_aether(upstream="socks5://127.0.0.1:1080", transport="h2")

    result = runner.invoke(app, ["aether", "register", "WARP"])
    assert result.exit_code == 0, result.output
    assert "Registering a free anonymous Cloudflare WARP device" in result.output
    assert "Registered 1/1" in result.output
    assert "[+] provisioned and saved new warp identity" in result.output  # Aether's own words, minus its log prefix

    (call,) = fake.calls
    env = call["env"]
    assert env["AETHER_REGISTER"] == "masque"
    assert env["AETHER_CONFIG"] == str(config_path(warp.id))
    assert env["AETHER_UPSTREAM"] == "socks5://127.0.0.1:1080"  # the registration goes through the carrier too
    assert call["stdin"] == subprocess.DEVNULL
    assert Path(call["cwd"]) == paths.aether_profile_dir(warp.id)


@pytest.mark.parametrize(
    "mode, which",
    [(AetherMode.WG, "wg"), (AetherMode.GOOL, "gool"), (AetherMode.GOOL_CLASSIC, "gool-classic"), (AetherMode.MIM, "mim")],
)
def test_register_asks_for_the_identities_of_the_mode(monkeypatch, aether_installed, mode, which):
    fake = FakeRun(creates=False)
    monkeypatch.setattr("v2rm.cli.aether.subprocess.run", fake)
    add_aether(mode=mode)
    runner.invoke(app, ["aether", "register", "WARP"])
    assert fake.calls[0]["env"]["AETHER_REGISTER"] == which


def test_register_does_not_inherit_aether_variables_from_the_shell(monkeypatch, aether_installed):
    fake = FakeRun()
    monkeypatch.setattr("v2rm.cli.aether.subprocess.run", fake)
    monkeypatch.setenv("AETHER_PEER", "1.2.3.4:443")
    monkeypatch.setenv("RUST_LOG", "trace")
    add_aether()
    runner.invoke(app, ["aether", "register", "WARP"])
    env = fake.calls[0]["env"]
    assert "AETHER_PEER" not in env and "RUST_LOG" not in env


def test_a_failed_registration_shows_what_aether_said(monkeypatch, aether_installed):
    monkeypatch.setattr("v2rm.cli.aether.subprocess.run", FakeRun(returncode=1, output="Error: api: 429 too many requests\n"))
    add_aether()
    result = runner.invoke(app, ["aether", "register", "WARP"])
    assert result.exit_code != 0
    assert "could not register" in str(result.exception) and "429" in str(result.exception)


def test_a_registration_that_never_finishes_times_out(monkeypatch, aether_installed):
    monkeypatch.setattr("v2rm.cli.aether.subprocess.run", FakeRun(timeout=True))
    add_aether()
    result = runner.invoke(app, ["aether", "register", "WARP", "--timeout", "5"])
    assert result.exit_code != 0 and "did not finish within 5 s" in str(result.exception)


def test_register_needs_aether_installed(monkeypatch):
    def missing(engine):
        raise EngineNotInstalledError("aether is not installed. Run `v2rm core install aether` first.")

    monkeypatch.setattr(supervisor, "_binary_path", missing)
    add_aether()
    result = runner.invoke(app, ["aether", "register", "WARP"])
    assert result.exit_code != 0 and "core install aether" in str(result.exception)


def test_only_aether_profiles_can_be_registered():
    add_trojan()
    result = runner.invoke(app, ["aether", "register", "trojan"])
    assert result.exit_code != 0 and "not an Aether profile" in str(result.exception)


# ---- gateways -----------------------------------------------------------------------------------------


CACHE = 'peer = "162.159.198.1:443"\nprofile = "gfw"\ncarrier = "masque-h3"\nrecent = [\n    "162.159.198.1:443",\n    "162.159.199.2:443",\n]\n'


def test_gateways_shows_identities_and_the_remembered_ring():
    warp = add_aether()
    directory = paths.aether_profile_dir(warp.id)
    directory.mkdir(parents=True)
    (directory / "aether-masque.toml").write_text("keys")
    (directory / "aether-masque-lastconn.toml").write_text(CACHE)

    result = runner.invoke(app, ["aether", "gateways", "WARP"])
    assert result.exit_code == 0, result.output
    out = result.output
    assert "1/1 registered" in out
    assert "162.159.198.1:443" in out and "162.159.199.2:443" in out and "masque-h3" in out
    assert "quick reconnect is on" in out


def test_gateways_before_anything_is_remembered():
    add_aether()
    result = runner.invoke(app, ["aether", "gateways", "WARP"])
    assert "0/1 registered" in result.output and "none remembered yet" in result.output


def test_gateways_forget_makes_the_next_start_scan_afresh():
    warp = add_aether()
    directory = paths.aether_profile_dir(warp.id)
    directory.mkdir(parents=True)
    cache = directory / "aether-masque-lastconn.toml"
    cache.write_text(CACHE)

    result = runner.invoke(app, ["aether", "gateways", "WARP", "--forget"])
    assert result.exit_code == 0 and "forgotten" in result.output
    assert not cache.exists()
    assert "nothing to forget" in runner.invoke(app, ["aether", "gateways", "WARP", "--forget"]).output


def test_gateways_for_modes_without_a_memory_says_how_to_skip_the_scan():
    add_aether(mode=AetherMode.GOOL_CLASSIC)
    result = runner.invoke(app, ["aether", "gateways", "WARP"])
    assert "keeps no memory of gateways" in result.output and "--outer" in result.output


# ---- env ------------------------------------------------------------------------------------------------


def test_env_prints_what_aether_is_given_with_secrets_hidden():
    warp = add_aether(
        transport="h2", noize="gfw", upstream="socks5://alice:hunter2@127.0.0.1:1080",
        route_block=["ads.example"], env={"AETHER_ACCESS_CLIENT_SECRET": "topsecret"},
    )
    result = runner.invoke(app, ["aether", "env", "WARP"])
    out = result.output
    assert result.exit_code == 0, out
    assert f"AETHER_CONFIG={config_path(warp.id)}" in out
    assert "AETHER_PROTOCOL=masque" in out and "AETHER_MASQUE_HTTP2=1" in out and "AETHER_NOIZE=gfw" in out
    assert "AETHER_SOCKS=127.0.0.1:10808" in out and "AETHER_HTTP_PROXY=127.0.0.1:10809" in out
    assert "hunter2" not in out and "topsecret" not in out
    assert "AETHER_UPSTREAM=socks5://alice:***@127.0.0.1:1080" in out


# ---- doctor ---------------------------------------------------------------------------------------------


def doctor() -> str:
    result = runner.invoke(app, ["doctor"])
    assert result.exit_code == 0, result.output
    return result.output


def test_doctor_is_quiet_about_aether_when_nobody_uses_it():
    out = doctor()
    assert "aether not installed (only needed for Aether profiles" in out
    assert "need it" not in out


def test_doctor_warns_when_an_aether_profile_has_no_aether():
    add_aether()
    assert "aether not installed, and 1 Aether profile(s) need it" in doctor()


def test_doctor_runs_the_installed_aether(monkeypatch):
    from v2rm.coredl import install as installer

    installer._install_binary("aether", "v2.3.0", b"x")
    installer.use_version("aether", "v2.3.0")
    monkeypatch.setattr("v2rm.cli.doctor.aether_runs", lambda binary: (True, "aether 2.3.0"))
    assert "aether installed (v2.3.0); it runs (aether 2.3.0)" in doctor()


def test_doctor_explains_a_glibc_mismatch(monkeypatch):
    from v2rm.coredl import install as installer

    installer._install_binary("aether", "v2.3.0", b"x")
    installer.use_version("aether", "v2.3.0")
    monkeypatch.setattr(
        "v2rm.cli.doctor.aether_runs", lambda binary: (False, "aether: /lib/libc.so.6: version `GLIBC_2.39' not found")
    )
    out = doctor()
    assert "cannot run" in out and "GLIBC_2.39" in out and "--variant musl" in out


def test_doctor_reports_a_broken_chain():
    from v2rm.models.chain import HOP_PROFILE, ChainHop

    warp, server = add_aether(), add_trojan()
    ProfileStore().add(
        Profile(
            name="c", protocol=Protocol.CHAIN,
            chain=[ChainHop(HOP_PROFILE, warp.id, warp.name), ChainHop(HOP_PROFILE, server.id, server.name)],
        )
    )
    ProfileStore().remove(server.id)
    assert "Chain 'c' can't run" in doctor()


def test_doctor_says_a_login_in_front_of_aether_needs_xray():
    from v2rm.models.auth import ProxyAuth
    from v2rm.store.auth import AuthStore

    add_aether()
    AuthStore().save(ProxyAuth("u", "p"))
    assert "needs Xray-core, which is not installed" in doctor()
