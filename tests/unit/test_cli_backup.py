from __future__ import annotations

from typer.testing import CliRunner

from v2rm.cli.app import app

runner = CliRunner()


def test_export_import_round_trip(tmp_path):
    runner.invoke(app, ["add", "trojan://pw@a.example.com:443?security=tls#AlphaProfile"])
    runner.invoke(app, ["profile", "use", "AlphaProfile"])

    backup_file = tmp_path / "backup.json"
    exported = runner.invoke(app, ["export", str(backup_file)])
    assert exported.exit_code == 0, exported.output
    assert backup_file.exists()

    removed = runner.invoke(app, ["profile", "remove", "AlphaProfile", "--force", "--yes"])
    assert removed.exit_code == 0, removed.output
    assert "AlphaProfile" not in runner.invoke(app, ["profile", "list"]).output

    imported = runner.invoke(app, ["import", str(backup_file)])
    assert imported.exit_code == 0, imported.output
    assert "AlphaProfile" in runner.invoke(app, ["profile", "list"]).output


def test_import_merge_is_idempotent_no_duplicates(tmp_path):
    runner.invoke(app, ["add", "trojan://pw@dup.example.com:443?security=tls#Dup"])
    backup_file = tmp_path / "backup2.json"
    runner.invoke(app, ["export", str(backup_file)])

    runner.invoke(app, ["import", str(backup_file)])
    runner.invoke(app, ["import", str(backup_file)])

    listed = runner.invoke(app, ["profile", "list"])
    assert listed.output.count("Dup") == 1


def test_import_missing_file_errors():
    result = runner.invoke(app, ["import", "/no/such/file.json"])
    assert result.exit_code != 0


def test_import_replace_clears_existing(tmp_path):
    runner.invoke(app, ["add", "trojan://pw@keep.example.com:443?security=tls#KeepMe"])
    backup_file = tmp_path / "backup3.json"
    runner.invoke(app, ["export", str(backup_file)])

    runner.invoke(app, ["add", "trojan://pw@extra.example.com:443?security=tls#Extra"])
    result = runner.invoke(app, ["import", str(backup_file), "--replace"])
    assert result.exit_code == 0, result.output

    listed = runner.invoke(app, ["profile", "list"])
    assert "KeepMe" in listed.output
    assert "Extra" not in listed.output


# ---- raw configs, MASQUE and the proxy login -----------------------------------------------------------------


def test_raw_configs_and_masque_profiles_survive_an_export_and_import(tmp_path):
    from tests.helpers import FIXTURES, load_json_fixture
    from v2rm.store.profiles import ProfileStore

    runner.invoke(app, ["add", "--json", str(FIXTURES / "serverless_subscription.json")])
    runner.invoke(app, ["add", "masque", "--server", "m.example.com", "--sni", "s", "--user", "alice", "--pass", "pw",
                        "--header", "X-A: 1", "--name", "M"])
    before = {p.name: p.to_dict() for p in ProfileStore().list()}
    assert len(before) == 3

    backup_file = tmp_path / "backup-raw.json"
    assert runner.invoke(app, ["export", str(backup_file)]).exit_code == 0
    for name in list(before):
        runner.invoke(app, ["profile", "remove", name, "--yes", "--force"])
    assert ProfileStore().list() == []

    assert runner.invoke(app, ["import", str(backup_file)]).exit_code == 0
    after = {p.name: p.to_dict() for p in ProfileStore().list()}
    assert after == before
    restored = next(p for p in ProfileStore().list() if p.is_raw and p.name == "Serverless-v52-fragA")
    assert restored.raw_config == load_json_fixture("serverless_subscription.json")[0]


def test_a_second_import_of_raw_configs_does_not_duplicate_them(tmp_path):
    from tests.helpers import FIXTURES
    from v2rm.store.profiles import ProfileStore

    runner.invoke(app, ["add", "--json", str(FIXTURES / "serverless_subscription.json")])
    backup_file = tmp_path / "backup-raw2.json"
    runner.invoke(app, ["export", str(backup_file)])
    runner.invoke(app, ["import", str(backup_file)])
    runner.invoke(app, ["import", str(backup_file)])
    assert len(ProfileStore().list()) == 2


def test_the_proxy_login_is_not_exported_and_the_user_is_told(tmp_path):
    runner.invoke(app, ["port", "set", "--auth", "demo:very-secret-pw"])
    backup_file = tmp_path / "backup-auth.json"
    result = runner.invoke(app, ["export", str(backup_file)])
    assert result.exit_code == 0, result.output
    assert "not included" in result.output and "set it again" in result.output
    assert "very-secret-pw" not in backup_file.read_text(encoding="utf-8")
    assert "demo" not in backup_file.read_text(encoding="utf-8")


def test_no_login_note_when_there_is_no_login(tmp_path):
    result = runner.invoke(app, ["export", str(tmp_path / "b.json")])
    assert "not included" not in result.output
