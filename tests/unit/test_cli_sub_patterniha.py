from __future__ import annotations

import json

import pytest
import requests
from typer.testing import CliRunner

from tests.helpers import free_links, read_fixture
from v2rm.cli.app import app
from v2rm.models.enums import Protocol
from v2rm.store.profiles import ProfileStore
from v2rm.store.subscriptions import SubscriptionStore

runner = CliRunner()

SERVERLESS_URL = (
    "https://raw.githubusercontent.com/patterniha/Serverless-for-Iran/refs/heads/main/"
    "Subscription/Serverless-for-Iran.json"
)
FREE_URL = "https://raw.githubusercontent.com/patterniha/Free-Configs/main/configs.txt"


class FakeResponse:
    def __init__(self, status_code: int = 200, text: str = ""):
        self.status_code = status_code
        self.text = text


@pytest.fixture
def web(monkeypatch):
    """Serve bodies by URL and record every URL that was actually requested."""
    state = {
        "bodies": {
            SERVERLESS_URL: read_fixture("serverless_subscription.json"),
            FREE_URL: read_fixture("free_configs_sample.txt"),
        },
        "calls": [],
    }

    def fake_get(url, headers=None, proxies=None, timeout=None, **kwargs):
        state["calls"].append(url)
        return FakeResponse(200, state["bodies"][url])

    monkeypatch.setattr(requests, "get", fake_get)
    return state


def add_both():
    a = runner.invoke(app, ["sub", "add", SERVERLESS_URL + "#Patterniha-S"])
    b = runner.invoke(app, ["sub", "add", FREE_URL + "#Patterniha-F"])
    assert a.exit_code == 0, a.output
    assert b.exit_code == 0, b.output


def test_url_fragment_becomes_the_name_and_is_never_sent(web):
    add_both()
    names = {s.name for s in SubscriptionStore().list()}
    assert names == {"Patterniha-S", "Patterniha-F"}
    assert web["calls"] == [SERVERLESS_URL, FREE_URL]  # no "#..." on the wire
    assert all("#" not in s.url for s in SubscriptionStore().list())


def test_serverless_subscription_becomes_two_raw_profiles(web):
    add_both()
    profiles = ProfileStore().list()
    raw = [p for p in profiles if p.protocol == Protocol.RAW_XRAY]
    assert sorted(p.name for p in raw) == ["Serverless-v52-fragA", "Serverless-v52-fragB"]
    assert all(p.subscription_id for p in raw)

    sub = SubscriptionStore().resolve("Patterniha-S")
    assert sub.format_hint.value == "xray_json"
    assert len(ProfileStore().list_by_subscription(sub.id)) == 2


def test_free_configs_count_matches_the_links_in_the_body(web):
    add_both()
    sub = SubscriptionStore().resolve("Patterniha-F")
    members = ProfileStore().list_by_subscription(sub.id)
    assert len(members) == len(free_links()) == 12
    assert sub.format_hint.value == "plain_list"
    assert {p.protocol for p in members} == {Protocol.VLESS, Protocol.TROJAN}


def test_provider_update_interval_is_stored_and_shown(web):
    add_both()
    sub = SubscriptionStore().resolve("Patterniha-F")
    assert sub.update_interval_hours == 1.0
    shown = runner.invoke(app, ["sub", "show", "Patterniha-F"])
    assert shown.exit_code == 0, shown.output
    assert "1h" in shown.output
    listed = runner.invoke(app, ["sub", "list"])
    assert "Patterniha-F" in listed.output and "Patterniha-S" in listed.output


def test_name_falls_back_to_profile_title_then_to_the_host(web):
    web["bodies"]["https://example.com/titled"] = "#profile-title: Titled One\n" + free_links()[0] + "\n"
    web["bodies"]["https://example.com/untitled"] = free_links()[1] + "\n"
    runner.invoke(app, ["sub", "add", "https://example.com/titled"])
    runner.invoke(app, ["sub", "add", "https://example.com/untitled"])
    assert {s.name for s in SubscriptionStore().list()} == {"Titled One", "example.com"}


def test_explicit_name_beats_fragment_and_title(web):
    web["bodies"]["https://example.com/t"] = "#profile-title: Title\n" + free_links()[0] + "\n"
    runner.invoke(app, ["sub", "add", "https://example.com/t#Fragment", "--name", "Explicit"])
    assert [s.name for s in SubscriptionStore().list()] == ["Explicit"]


def test_fragment_beats_profile_title(web):
    web["bodies"]["https://example.com/t"] = "#profile-title: Title\n" + free_links()[0] + "\n"
    runner.invoke(app, ["sub", "add", "https://example.com/t#Fragment"])
    assert [s.name for s in SubscriptionStore().list()] == ["Fragment"]


def test_percent_encoded_fragment_is_decoded(web):
    runner.invoke(app, ["sub", "add", FREE_URL + "#My%20Free%20Configs"])
    assert [s.name for s in SubscriptionStore().list()] == ["My Free Configs"]


def test_second_update_adds_and_removes_nothing_and_keeps_ids(web):
    add_both()
    before = {p.id: p.name for p in ProfileStore().list()}
    assert len(before) == 14

    result = runner.invoke(app, ["sub", "update", "--all"])
    assert result.exit_code == 0, result.output
    assert "+0 ~0 -0" in result.output.replace("\n", " ")

    after = {p.id: p.name for p in ProfileStore().list()}
    assert after == before


def test_changed_raw_body_with_same_remarks_updates_in_place(web):
    add_both()
    frag_a = next(p for p in ProfileStore().list() if p.name == "Serverless-v52-fragA")

    body = json.loads(web["bodies"][SERVERLESS_URL])
    body[0]["policy"] = {"levels": {"0": {"connIdle": 99}}}
    web["bodies"][SERVERLESS_URL] = json.dumps(body)

    result = runner.invoke(app, ["sub", "update", "Patterniha-S"])
    assert result.exit_code == 0, result.output
    assert "~1" in result.output

    again = ProfileStore().get(frag_a.id)
    assert again is not None  # same id: updated in place, not removed and re-added
    assert again.raw_config["policy"] == {"levels": {"0": {"connIdle": 99}}}
    assert len(ProfileStore().list()) == 14


def test_update_all_without_respect_interval_always_refreshes(web):
    add_both()
    web["calls"].clear()
    runner.invoke(app, ["sub", "update", "--all"])
    assert FREE_URL in web["calls"]  # refreshed even though it was added a moment ago


def test_respect_interval_skips_a_recently_refreshed_subscription_only(web):
    add_both()
    web["calls"].clear()
    result = runner.invoke(app, ["sub", "update", "--all", "--respect-interval"])
    assert result.exit_code == 0, result.output
    assert web["calls"] == [SERVERLESS_URL]  # no provider interval -> refreshed; Free-Configs (1h) -> skipped
    assert "skipped" in result.output


def test_respect_interval_is_overridden_by_force_and_by_naming_the_subscription(web):
    add_both()
    web["calls"].clear()
    runner.invoke(app, ["sub", "update", "--all", "--respect-interval", "--force"])
    assert FREE_URL in web["calls"]

    web["calls"].clear()
    runner.invoke(app, ["sub", "update", "Patterniha-F", "--respect-interval"])
    assert FREE_URL in web["calls"]


def test_an_outage_page_does_not_wipe_the_existing_profiles(web):
    add_both()
    web["bodies"][FREE_URL] = "<html><body>503 Service Unavailable</body></html>"

    result = runner.invoke(app, ["sub", "update", "Patterniha-F"])
    assert result.exit_code == 0, result.output
    assert "keeping the existing 12" in result.output.replace("\n", " ")

    sub = SubscriptionStore().resolve("Patterniha-F")
    assert len(ProfileStore().list_by_subscription(sub.id)) == 12
    assert sub.last_status.startswith("error")


def test_adding_a_body_with_no_usable_profiles_adds_nothing(web):
    web["bodies"]["https://example.com/junk"] = "<html>not a subscription</html>"
    result = runner.invoke(app, ["sub", "add", "https://example.com/junk"])
    assert result.exit_code != 0
    # (CliRunner bypasses main()'s error printer, so the message is on the exception.)
    assert "Nothing was added" in str(result.exception)
    assert "plain_list" in str(result.exception)
    assert SubscriptionStore().list() == []
    assert ProfileStore().list() == []


def test_base64_encoded_free_configs_with_comment_header_imports(web):
    import base64

    encoded = base64.b64encode("\n".join(free_links()).encode()).decode()
    web["bodies"]["https://example.com/b64"] = "#profile-title: Encoded\n#profile-update-interval: 2\n" + encoded
    result = runner.invoke(app, ["sub", "add", "https://example.com/b64"])
    assert result.exit_code == 0, result.output
    sub = SubscriptionStore().resolve("Encoded")
    assert sub.format_hint.value == "base64_list"
    assert sub.update_interval_hours == 2.0
    assert len(ProfileStore().list_by_subscription(sub.id)) == 12


def test_sub_remove_cascades_to_raw_profiles(web):
    add_both()
    runner.invoke(app, ["sub", "remove", "Patterniha-S", "--yes"])
    assert not [p for p in ProfileStore().list() if p.protocol == Protocol.RAW_XRAY]
    assert len(ProfileStore().list()) == 12
