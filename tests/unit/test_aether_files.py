"""Where Aether keeps a profile's identities and its cache of working gateways."""

from __future__ import annotations

from pathlib import Path

from v2rm.engines.aether import files
from v2rm.models.aether import AetherMode
from v2rm.store import paths

BASE = Path("/d/aether/p1/aether.toml")


def names(found: list[Path]) -> list[str]:
    return [p.name for p in found]


def test_siblings_are_named_the_way_aether_names_them():
    assert files.derive_sibling(BASE, "masque").name == "aether-masque.toml"
    assert files.derive_sibling(files.derive_sibling(BASE, "masque"), "gool").name == "aether-masque-gool.toml"
    assert files.derive_sibling(Path("/x/noext"), "secondary").name == "noext-secondary"
    assert files.derive_sibling(BASE, "lastconn").parent == BASE.parent


def test_the_identities_each_mode_needs():
    assert names(files.identity_files(BASE, AetherMode.MASQUE)) == ["aether-masque.toml"]
    assert names(files.identity_files(BASE, AetherMode.WG)) == ["aether.toml"]
    assert names(files.identity_files(BASE, AetherMode.GOOL)) == ["aether-masque.toml", "aether-masque-gool.toml"]
    assert names(files.identity_files(BASE, AetherMode.GOOL_CLASSIC)) == ["aether.toml", "aether-secondary.toml"]
    assert names(files.identity_files(BASE, AetherMode.MIM)) == ["aether-masque.toml", "aether-masque-secondary.toml"]


def test_the_gateway_cache_exists_only_where_aether_keeps_one():
    assert files.lastconn_file(BASE, AetherMode.MASQUE).name == "aether-masque-lastconn.toml"
    assert files.lastconn_file(BASE, AetherMode.GOOL).name == "aether-masque-lastconn.toml"
    assert files.lastconn_file(BASE, AetherMode.WG).name == "aether-lastconn.toml"
    assert files.lastconn_file(BASE, AetherMode.GOOL_CLASSIC) is None
    assert files.lastconn_file(BASE, AetherMode.MIM) is None


def test_the_config_path_lives_in_the_profiles_own_folder():
    assert files.config_path("abc123") == paths.aether_dir() / "abc123" / "aether.toml"


def test_registration_state_counts_existing_identity_files(tmp_path):
    base = tmp_path / "aether.toml"
    assert files.identity_state(base, AetherMode.GOOL) == (0, 2)
    (tmp_path / "aether-masque.toml").write_text("x")
    assert files.identity_state(base, AetherMode.GOOL) == (1, 2)
    (tmp_path / "aether-masque-gool.toml").write_text("x")
    assert files.identity_state(base, AetherMode.GOOL) == (2, 2)


# ---- the gateway cache, as Aether's toml serialiser writes it -----------------------------------


PRETTY = """\
peer = "162.159.198.1:443"
profile = "firewall"
carrier = "masque-h3"
recent = [
    "162.159.198.1:443",
    "162.159.199.2:443",
]
"""


def test_the_cache_is_read(tmp_path):
    path = tmp_path / "aether-masque-lastconn.toml"
    path.write_text(PRETTY)
    cache = files.read_last_gateways(path)
    assert cache.peer == "162.159.198.1:443"
    assert cache.carrier == "masque-h3" and cache.profile == "firewall"
    assert cache.recent == ["162.159.198.1:443", "162.159.199.2:443"]


def test_the_cache_from_an_older_build_has_only_a_peer(tmp_path):
    path = tmp_path / "c.toml"
    path.write_text('peer = "1.1.1.1:443"\nprofile = "gfw"\n')
    cache = files.read_last_gateways(path)
    assert cache.peer == "1.1.1.1:443" and cache.recent == [] and cache.carrier == ""


def test_a_one_line_array_and_an_empty_one(tmp_path):
    path = tmp_path / "c.toml"
    path.write_text('peer = "1.1.1.1:443"\nrecent = ["1.1.1.1:443", "2.2.2.2:443"]\n')
    assert files.read_last_gateways(path).recent == ["1.1.1.1:443", "2.2.2.2:443"]
    path.write_text('peer = "1.1.1.1:443"\nrecent = []\n')
    assert files.read_last_gateways(path).recent == []


def test_a_missing_or_empty_cache_is_none(tmp_path):
    assert files.read_last_gateways(tmp_path / "missing.toml") is None
    assert files.read_last_gateways(None) is None
    (tmp_path / "empty.toml").write_text("")
    assert files.read_last_gateways(tmp_path / "empty.toml") is None
    (tmp_path / "junk.toml").write_text("not = = toml [[[")
    assert files.read_last_gateways(tmp_path / "junk.toml") is None


def test_forgetting_the_cache(tmp_path):
    path = tmp_path / "c.toml"
    assert files.forget_last_gateways(path) is False
    path.write_text(PRETTY)
    assert files.forget_last_gateways(path) is True
    assert not path.exists()
    assert files.forget_last_gateways(None) is False


def test_removing_a_profiles_state_deletes_its_identities(tmp_path):
    directory = paths.aether_profile_dir("gone")
    directory.mkdir(parents=True)
    (directory / "aether-masque.toml").write_text("secret")
    assert files.remove_profile_state("gone") is True
    assert not directory.exists()
    assert files.remove_profile_state("gone") is False
