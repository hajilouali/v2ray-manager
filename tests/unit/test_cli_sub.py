from __future__ import annotations

import base64

import requests
from typer.testing import CliRunner

from v2rm.cli.app import app

runner = CliRunner()


class FakeResponse:
    def __init__(self, status_code: int = 200, text: str = ""):
        self.status_code = status_code
        self.text = text


def _mock_fetch(monkeypatch, body: str) -> None:
    monkeypatch.setattr(requests, "get", lambda *a, **k: FakeResponse(200, body))


def test_sub_add_plain_list(monkeypatch):
    body = "trojan://pw@a.example.com:443#First\ntrojan://pw@b.example.com:443#Second"
    _mock_fetch(monkeypatch, body)

    result = runner.invoke(app, ["sub", "add", "https://example.com/sub", "--name", "MySub"])
    assert result.exit_code == 0, result.output
    assert "MySub" in result.output

    listed = runner.invoke(app, ["profile", "list"])
    assert "First" in listed.output
    assert "Second" in listed.output

    sub_listed = runner.invoke(app, ["sub", "list"])
    assert "MySub" in sub_listed.output


def test_sub_add_base64_list(monkeypatch):
    raw = "trojan://pw@c.example.com:443#Third"
    _mock_fetch(monkeypatch, base64.b64encode(raw.encode()).decode())

    result = runner.invoke(app, ["sub", "add", "https://example.com/sub2", "--name", "B64Sub"])
    assert result.exit_code == 0, result.output

    listed = runner.invoke(app, ["profile", "list", "--subscription", "B64Sub"])
    assert "Third" in listed.output


def test_sub_add_clash_yaml(monkeypatch):
    yaml_body = (
        "proxies:\n"
        "  - name: ClashNode\n"
        "    type: trojan\n"
        "    server: clash.example.com\n"
        "    port: 443\n"
        "    password: pw\n"
    )
    _mock_fetch(monkeypatch, yaml_body)

    result = runner.invoke(app, ["sub", "add", "https://example.com/sub-clash", "--name", "ClashSub"])
    assert result.exit_code == 0, result.output

    listed = runner.invoke(app, ["profile", "list"])
    assert "ClashNode" in listed.output


def test_sub_update_adds_and_removes_members(monkeypatch):
    _mock_fetch(monkeypatch, "trojan://pw@u1.example.com:443#Keep\ntrojan://pw@u2.example.com:443#WillGoAway")
    runner.invoke(app, ["sub", "add", "https://example.com/sub3", "--name", "UpdSub"])

    _mock_fetch(monkeypatch, "trojan://pw@u1.example.com:443#Keep\ntrojan://pw@u3.example.com:443#NewOne")
    result = runner.invoke(app, ["sub", "update", "UpdSub"])
    assert result.exit_code == 0, result.output

    listed = runner.invoke(app, ["profile", "list", "--subscription", "UpdSub"])
    assert "Keep" in listed.output
    assert "NewOne" in listed.output
    assert "WillGoAway" not in listed.output


def test_sub_update_protects_active_profile_without_force(monkeypatch):
    _mock_fetch(monkeypatch, "trojan://pw@keep-active.example.com:443#ActiveOne")
    runner.invoke(app, ["sub", "add", "https://example.com/sub5", "--name", "ProtSub"])

    used = runner.invoke(app, ["profile", "use", "ActiveOne"])
    assert used.exit_code == 0, used.output

    _mock_fetch(monkeypatch, "trojan://pw@totally-different.example.com:443#Different")
    result = runner.invoke(app, ["sub", "update", "ProtSub"])
    assert result.exit_code == 0, result.output
    assert "Skipped removing the active" in result.output

    still_there = runner.invoke(app, ["profile", "list"])
    assert "ActiveOne" in still_there.output


def test_sub_remove_cascades_profiles(monkeypatch):
    _mock_fetch(monkeypatch, "trojan://pw@rm1.example.com:443#RmMember")
    runner.invoke(app, ["sub", "add", "https://example.com/sub4", "--name", "RmSub"])

    result = runner.invoke(app, ["sub", "remove", "RmSub", "--yes"])
    assert result.exit_code == 0, result.output

    listed = runner.invoke(app, ["profile", "list"])
    assert "RmMember" not in listed.output


def test_sub_update_all(monkeypatch):
    _mock_fetch(monkeypatch, "trojan://pw@all1.example.com:443#All1")
    runner.invoke(app, ["sub", "add", "https://example.com/sub6", "--name", "AllSub1"])
    _mock_fetch(monkeypatch, "trojan://pw@all2.example.com:443#All2")
    runner.invoke(app, ["sub", "add", "https://example.com/sub7", "--name", "AllSub2"])

    result = runner.invoke(app, ["sub", "update", "--all"])
    assert result.exit_code == 0, result.output
    assert "AllSub1" in result.output
    assert "AllSub2" in result.output


def test_sub_update_keeps_a_dropped_node_that_a_chain_uses(monkeypatch):
    from v2rm.models.aether import AetherSettings
    from v2rm.models.chain import HOP_PROFILE, ChainHop
    from v2rm.models.enums import Protocol
    from v2rm.models.profile import Profile
    from v2rm.store.profiles import ProfileStore

    _mock_fetch(monkeypatch, "trojan://pw@k1.example.com:443#Keep\ntrojan://pw@k2.example.com:443#Used")
    runner.invoke(app, ["sub", "add", "https://example.com/sub-chain", "--name", "ChainSub"])
    store = ProfileStore()
    warp = store.add(Profile(name="WARP", protocol=Protocol.AETHER, aether=AetherSettings()))
    used = next(p for p in store.list() if p.name == "Used")
    store.add(
        Profile(
            name="via-warp",
            protocol=Protocol.CHAIN,
            chain=[ChainHop(HOP_PROFILE, warp.id, warp.name), ChainHop(HOP_PROFILE, used.id, used.name)],
        )
    )

    _mock_fetch(monkeypatch, "trojan://pw@k1.example.com:443#Keep")  # the provider dropped "Used"
    result = runner.invoke(app, ["sub", "update", "ChainSub"])
    assert result.exit_code == 0, result.output
    assert "chain(s) use them: via-warp" in result.output
    assert any(p.name == "Used" for p in ProfileStore().list())

    forced = runner.invoke(app, ["sub", "update", "ChainSub", "--force"])
    assert forced.exit_code == 0, forced.output
    assert not any(p.name == "Used" for p in ProfileStore().list())


def test_sub_remove_warns_about_chains_that_use_its_profiles(monkeypatch):
    from v2rm.models.chain import HOP_PROFILE, ChainHop
    from v2rm.models.enums import Protocol
    from v2rm.models.profile import Profile
    from v2rm.store.profiles import ProfileStore

    _mock_fetch(monkeypatch, "trojan://pw@r1.example.com:443#Member\ntrojan://pw@r2.example.com:443#Other")
    runner.invoke(app, ["sub", "add", "https://example.com/sub-rm", "--name", "RmSub"])
    store = ProfileStore()
    member, other = (next(p for p in store.list() if p.name == n) for n in ("Member", "Other"))
    store.add(
        Profile(
            name="uses-sub",
            protocol=Protocol.CHAIN,
            chain=[ChainHop(HOP_PROFILE, member.id, "Member"), ChainHop(HOP_PROFILE, other.id, "Other")],
        )
    )
    # The chain is not a member of the subscription, so removing the subscription leaves it behind
    # (broken); the command says so before it goes ahead.
    result = runner.invoke(app, ["sub", "remove", "RmSub", "--yes"])
    assert result.exit_code == 0, result.output
    assert "will stop working: uses-sub" in result.output
