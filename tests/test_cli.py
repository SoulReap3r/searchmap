"""CLI entry points. The scan test runs fully offline (no network, no
fingerprinting) so it is hermetic: it exercises ingest -> serialize -> report."""
import json
import pathlib

from smap import cli

FIX = str(pathlib.Path(__file__).parent / "fixtures" / "scan.xml")


def test_version(capsys):
    assert cli.main(["--version"]) == 0
    assert "searchmap 3.0" in capsys.readouterr().out


def test_help():
    assert cli.main(["--help"]) == 0


def test_scan_offline_json(tmp_path, capsys):
    out = tmp_path / "scan.json"
    rc = cli.main(["--xml", FIX, "--offline", "--no-fp", "--format", "json", "-o", str(out)])
    assert rc == 0
    data = json.loads(out.read_text())
    assert data["tool_version"] == "3.0.0"
    assert data["profile"] == "exam"
    ips = [h["ip"] for h in data["hosts"]]
    assert ips == ["10.10.10.5"]
    ports = {s["port"] for s in data["hosts"][0]["services"]}
    assert {21, 22, 80, 445, 3389} <= ports


def test_report_json_to_html(tmp_path):
    scan = tmp_path / "scan.json"
    cli.main(["--xml", FIX, "--offline", "--no-fp", "--format", "json", "-o", str(scan)])
    htmlf = tmp_path / "out.html"
    rc = cli.main(["report", str(scan), "--format", "html", "-o", str(htmlf)])
    assert rc == 0
    body = htmlf.read_text()
    assert body.startswith("<!doctype html>") and "10.10.10.5" in body


def test_scan_requires_target():
    import pytest
    with pytest.raises(SystemExit):   # argparse error -> exit 2
        cli.main([])
