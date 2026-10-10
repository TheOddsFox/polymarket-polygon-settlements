import json
import subprocess

import pytest

from polymarket_polygon_settlements import smoke


def test_failed_command_keeps_stdout_accounting(monkeypatch, tmp_path):
    result = subprocess.CompletedProcess(
        [], 2, '{"http_attempts": 2, "downloaded_bytes": 17}', "warning"
    )
    monkeypatch.setattr(smoke.subprocess, "run", lambda *a, **k: result)
    report = {"steps": []}
    with pytest.raises(smoke.SmokeFailure):
        smoke.command(report, "lookup", ["unused"])
    assert smoke.finish(tmp_path, report, smoke.SmokeFailure("lookup failed")) == 1
    saved = json.loads((tmp_path / "report.json").read_text())
    assert saved["http_attempts"] == 2
    assert saved["downloaded_bytes"] == 17
    assert saved["accounting_complete"] is False


def test_last_stderr_json_and_invalid_diagnostics(monkeypatch):
    result = subprocess.CompletedProcess([], 1, "", 'started\n{"message":"rejected"}\n')
    monkeypatch.setattr(smoke.subprocess, "run", lambda *a, **k: result)
    report = {"steps": []}
    with pytest.raises(smoke.SmokeFailure, match="rejected"):
        smoke.command(report, "scan", ["unused"])
    result.stdout, result.stderr, result.returncode = "[]", "", 0
    with pytest.raises(smoke.SmokeFailure, match="invalid JSON"):
        smoke.command(report, "scan", ["unused"])


def test_timeout_does_not_claim_complete_accounting(monkeypatch, tmp_path):
    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired("unused", 180)

    monkeypatch.setattr(smoke.subprocess, "run", timeout)
    report = {"steps": []}
    with pytest.raises(subprocess.TimeoutExpired) as error:
        smoke.command(report, "scan", ["unused"])
    smoke.finish(tmp_path, report, error.value)
    assert report["accounting_complete"] is False
    assert report["error"] == "TimeoutExpired"


def test_output_never_reuses_existing_or_symlink_root(tmp_path):
    with pytest.raises(smoke.SmokeFailure, match="fresh"):
        smoke.new_output(tmp_path)
    link = tmp_path / "link"
    link.symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(smoke.SmokeFailure, match="symlink"):
        smoke.new_output(link / "new")
    assert smoke.new_output(tmp_path / "new") == tmp_path / "new"


def test_consumer_report_is_bounded_and_has_correct_producer(tmp_path):
    path = tmp_path / "report.json"
    path.write_bytes(b" " * 1048577)
    with pytest.raises(smoke.SmokeFailure, match="exceeds"):
        smoke.load_report(path)
    path.write_text('{"product":"another-product","status":"passed"}')
    with pytest.raises(smoke.SmokeFailure, match="producer"):
        smoke.load_report(path)


def test_initial_rpc_failure_retains_attempt_accounting(monkeypatch, tmp_path):
    from polymarket_polygon_settlements import rpc, transport

    class Client:
        requests = 2
        downloaded = 21

        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

    def fail(*args):
        raise transport.SourceError("failed", "source request failed")

    monkeypatch.setattr(transport, "Client", Client)
    monkeypatch.setattr(rpc.RPC, "block", fail)
    report = {"steps": []}
    with pytest.raises(transport.SourceError) as error:
        smoke.run(tmp_path, {"status": "passed"}, 20, report)
    smoke.finish(tmp_path, report, error.value)
    assert report["http_attempts"] == 2
    assert report["downloaded_bytes"] == 21
    assert report["accounting_complete"] is False


def test_live_verify_cli_reports_transport_totals(monkeypatch, tmp_path):
    from types import SimpleNamespace

    from polymarket_polygon_settlements import cli

    class Client:
        requests = 3
        downloaded = 51

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

    store = SimpleNamespace(verify=lambda release: {"verified": True})
    monkeypatch.setattr(cli, "Store", lambda *args: store)
    monkeypatch.setattr(cli, "rpc_client", lambda *args: (Client(), None))
    monkeypatch.setattr(cli, "live_verify", lambda *args: {"rpc_calls": 3})
    args = SimpleNamespace(
        command="verify", root=tmp_path, release=None, live=True, max_requests=20
    )
    result = cli.run(args)
    assert result["http_attempts"] == 3
    assert result["downloaded_bytes"] == 51


def test_consumer_rejects_incomplete_and_untyped_identity(tmp_path):
    path = tmp_path / "report.json"
    source = {"product": "polymarket-events", "status": "passed", "accounting_complete": False}
    path.write_text(json.dumps(source))
    with pytest.raises(smoke.SmokeFailure, match="accounting"):
        smoke.load_report(path)
    source["accounting_complete"] = True
    source.update(metadata=[], metadata_sha256="a", market_id="1")
    path.write_text(json.dumps(source))
    with pytest.raises(smoke.SmokeFailure, match="identity"):
        smoke.load_report(path)
