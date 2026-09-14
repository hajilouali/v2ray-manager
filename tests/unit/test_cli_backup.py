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
