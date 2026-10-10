"""Explicit live smoke; ordinary tests and CI never invoke this module."""

import argparse
import json
import os
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4


class SmokeFailure(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise SmokeFailure(message)


def command(report, name, argv, env=None):
    step = {"name": name}
    report["steps"].append(step)
    result = subprocess.run(argv, env=env, capture_output=True, text=True, timeout=180)
    step["exit_code"] = result.returncode
    try:
        value = json.loads(result.stdout)
    except ValueError:
        try:
            value = json.loads(result.stderr.strip().splitlines()[-1])
        except (ValueError, IndexError):
            raise SmokeFailure(name + ": missing JSON diagnostics") from None
    require(isinstance(value, dict), name + ": invalid JSON diagnostics")
    for key in ("http_attempts", "requests", "downloaded_bytes"):
        require(
            key not in value or (type(value[key]) is int and value[key] >= 0),
            name + ": invalid accounting diagnostics",
        )
    require(
        "message" not in value or isinstance(value["message"], str),
        name + ": invalid error diagnostics",
    )
    step["result"] = value
    require(result.returncode == 0, name + ": " + value.get("message", "command failed"))
    return value


def finish(output, report, error=None):
    report["status"] = "failed" if error else "passed"
    if error:
        report["error"] = str(error) if isinstance(error, SmokeFailure) else type(error).__name__
    report["finished_at"] = datetime.now(UTC).isoformat()
    report["http_attempts"] = sum(
        step.get("result", {}).get("http_attempts", step.get("result", {}).get("requests", 0))
        for step in report["steps"]
    )
    report["downloaded_bytes"] = sum(
        step.get("result", {}).get("downloaded_bytes", 0) for step in report["steps"]
    )
    report["accounting_complete"] = bool(report["steps"]) and all(
        "result" in step and step.get("exit_code") == 0 for step in report["steps"]
    )
    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(
        json.dumps(
            {
                "status": report["status"],
                "report": str(output / "report.json"),
                "http_attempts": report["http_attempts"],
                "downloaded_bytes": report["downloaded_bytes"],
                "error": report.get("error"),
            },
            indent=2,
        )
    )
    return 1 if error else 0


def new_output(value):
    output = (value or Path("data/smoke") / uuid4().hex).absolute()
    require(not output.exists(), "output must be a fresh directory")
    require(not any(path.is_symlink() for path in (output, *output.parents)), "symlink output")
    return output


def run(output, source, blocks, report):
    import pyarrow.parquet as pq

    from .foundation import Limits
    from .rpc import RPC
    from .transport import Client

    require(source["status"] == "passed", "events smoke did not pass")
    endpoint = os.environ.get("POLYGON_RPC_URL", "https://polygon-bor-rpc.publicnode.com")
    os.environ["POLYGON_RPC_URL"] = endpoint
    step = {"name": "finalized_head"}
    report["steps"].append(step)
    with Client(
        "rpc", Limits(5, 1048576, 67108864, 1048576, 67108864), rpc_url=endpoint, retries=1
    ) as client:
        try:
            rpc = RPC(lambda body: client.post_json(endpoint, body), max_calls=5)
            head = rpc.block("finalized")
            step["exit_code"] = 0
        finally:
            step["result"] = {
                "http_attempts": client.requests,
                "downloaded_bytes": client.downloaded,
            }
    step["result"].update(number=head.number, hash=head.hash)
    cli = [sys.executable, "-m", "polymarket_polygon_settlements.cli", "--root", str(output)]
    plan = command(
        report,
        "plan",
        [
            *cli,
            "plan",
            "--metadata",
            source["metadata"],
            "--metadata-digest",
            source["metadata_sha256"],
            "--market",
            source["market_id"],
            "--exchange",
            "standard",
            "--from-block",
            str(head.number - blocks),
            "--to-block",
            str(head.number - 1),
            "--max-blocks",
            str(blocks),
            "--max-requests",
            "100",
            "--max-download-bytes",
            "8388608",
            "--max-storage-bytes",
            "67108864",
            "--max-response-bytes",
            "1048576",
            "--max-temp-bytes",
            "67108864",
        ],
    )["plan_id"]
    acquisition = command(report, "scan", [*cli, "scan", "--plan", plan])["acquisition_id"]
    command(report, "scan_resume", [*cli, "scan", "--plan", plan, "--resume", acquisition])
    build_args = [*cli, "build", "--plan", plan, "--acquisition", acquisition]
    release = command(report, "build", build_args)["release_id"]
    require(command(report, "replay", build_args)["release_id"] == release, "semantic replay drift")
    command(report, "publish", [*cli, "publish", "--release", release])
    command(report, "verify_live", [*cli, "verify", "--live", "--max-requests", "20"])
    directory = output / "published" / release
    legs = pq.read_table(directory / "economic_legs.parquet").num_rows
    report.update(
        plan_id=plan,
        release_id=release,
        economic_legs=legs,
        coverage=json.loads((directory / "coverage.json").read_text()),
        checks=[
            "chain_target_proof",
            "finalized_scan",
            "resume",
            "offline_replay",
            "publish",
            "live_hash_verification",
        ],
        fill_decoding="observed" if legs else "not_exercised_empty_interval",
    )
    require(
        legs > 0, "finalized scan is empty; fill decoding not exercised; rerun with --blocks 100"
    )


def load_report(path):
    require(path.is_file() and not path.is_symlink(), "events report must be a regular file")
    with path.open("rb") as handle:
        raw = handle.read(1048577)
    require(len(raw) <= 1048576, "events report exceeds 1 MiB")
    source = json.loads(raw)
    require(isinstance(source, dict), "invalid events report")
    require(source.get("product") == "polymarket-events", "wrong producer report")
    require(
        source.get("status") == "passed" and source.get("accounting_complete") is True,
        "events smoke did not pass with complete accounting",
    )
    for key in ("metadata", "metadata_sha256", "market_id"):
        require(isinstance(source.get(key), str) and bool(source[key]), "invalid producer identity")
    return source


def main(argv=None):
    from .foundation import Store

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--events-report", required=True, type=Path)
    parser.add_argument("--blocks", type=int, default=20)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    require(1 <= args.blocks <= 100, "blocks must be 1..100")
    output = new_output(args.output)
    Store(output, "oddsfox.polymarket.polygon-settlements.v1")
    report = {
        "product": "polymarket-polygon-settlements",
        "steps": [],
        "started_at": datetime.now(UTC).isoformat(),
        "limits": {
            "attempts_per_command": 100,
            "download_bytes_per_command": 8388608,
            "retained_bytes": 67108864,
            "blocks": args.blocks,
            "finalized_discovery": {"attempts": 5, "download_bytes": 1048576},
            "live_verify": {"attempts": 20, "download_bytes": 268435456},
        },
    }
    try:
        run(output, load_report(args.events_report), args.blocks, report)
    except (ValueError, OSError, subprocess.TimeoutExpired, KeyError) as error:
        return finish(output, report, error)
    return finish(output, report)


if __name__ == "__main__":
    raise SystemExit(main())
