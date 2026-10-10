"""Finite local CTF settlement collection and reproducible publication."""

import argparse
import json
import os
import sys
from pathlib import Path

from filelock import Timeout

from .codec import ABI_REVISION, NEG_RISK_EXCHANGE, STANDARD_EXCHANGE, PolygonError, RangeLimit
from .foundation import BudgetExceeded, Limits, Store, json_bytes
from .metadata import pin_metadata, select_assets
from .pipeline import CONTRACT, build, live_verify, publish, published_legs, scan
from .rpc import RPC, finalized_plan
from .transport import Client, SourceError


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        prog="polymarket-polygon-settlements",
        description="Bounded finalized CTF Exchange V2 economic data",
    )
    result.add_argument("--root", default="./data")
    commands = result.add_subparsers(dest="command", required=True)
    plan = commands.add_parser("plan")
    plan.add_argument("--metadata", required=True, type=Path)
    plan.add_argument("--metadata-digest", required=True)
    plan.add_argument("--market", action="append", required=True)
    plan.add_argument("--exchange", choices=["standard", "neg-risk"], required=True)
    plan.add_argument("--from-block", type=int, required=True)
    plan.add_argument("--to-block", type=int, required=True)
    plan.add_argument("--max-blocks", type=int, default=20_000)
    plan.add_argument("--max-logs", type=int, default=10_000)
    plan.add_argument("--max-buckets", type=int, default=100_000)
    for name, default in (
        ("max-requests", 1000),
        ("max-download-bytes", 256 * 1024**2),
        ("max-storage-bytes", 1024**3),
        ("max-response-bytes", 16 * 1024**2),
        ("max-temp-bytes", 256 * 1024**2),
    ):
        plan.add_argument("--" + name, type=int, default=default)
    collect = commands.add_parser("scan")
    collect.add_argument("--plan", required=True)
    collect.add_argument("--resume")
    project = commands.add_parser("build")
    project.add_argument("--plan", required=True)
    project.add_argument("--acquisition", action="append", required=True)
    publish = commands.add_parser("publish")
    publish.add_argument("--release", required=True)
    verify = commands.add_parser("verify")
    verify.add_argument("--release")
    verify.add_argument("--live", action="store_true")
    verify.add_argument("--max-requests", type=int, default=1000)
    union = commands.add_parser(
        "published-legs", help="Canonical deduplicated union across active plans"
    )
    union.add_argument("--max-temp-bytes", type=int, required=True)
    commands.add_parser("status")
    return result


def endpoint() -> str:
    value = os.environ.get("POLYGON_RPC_URL")
    if not value:
        raise PolygonError("Set POLYGON_RPC_URL to an explicit HTTPS read-only endpoint")
    return value


def rpc_client(store: Store, limits: Limits):
    url = endpoint()
    client = Client("rpc", limits, rpc_url=url, storage_root=store.root)

    def post(body):
        try:
            return client.post_json(url, body)
        except SourceError as exc:
            if exc.status == "range_limit":
                raise RangeLimit("RPC response range limit") from None
            raise

    return client, RPC(post, max_calls=limits.max_requests)


def run(args) -> dict:
    if args.command == "plan":
        limits = Limits(**{key: getattr(args, key) for key in Limits.__dataclass_fields__})
        if (
            min(args.max_blocks, args.max_logs, args.max_buckets) <= 0
            or args.to_block - args.from_block + 1 > args.max_blocks
        ):
            raise PolygonError("Finite block/log/bucket bounds exceeded")
        store = Store(args.root, CONTRACT, limits)
        with store.lock:
            bundle = pin_metadata(store.root, args.metadata, args.metadata_digest, store=store)
            assets = select_assets(bundle, args.market)
            # Position rejection happens before creating a transport or any RPC call.
            if any(asset["asset_kind"] != "ctf_token" for asset in assets):
                raise PolygonError("Protocol V2 positions are outside CTF settlement v1")
            client, rpc = rpc_client(store, limits)
            with client:
                exchange = STANDARD_EXCHANGE if args.exchange == "standard" else NEG_RISK_EXCHANGE
                data = finalized_plan(
                    rpc,
                    bundle.markets,
                    assets,
                    args.market,
                    [exchange],
                    args.from_block,
                    args.to_block,
                )
            estimated = (
                (data["end_timestamp_exclusive"] - 1) // 60 - data["start_timestamp"] // 60 + 1
            ) * len(assets)
            if estimated > args.max_buckets:
                raise PolygonError("Requested aggregate bucket bound exceeded")
            plan_id = store.create_plan(
                {
                    **data,
                    "limits": limits.as_dict(),
                    "max_blocks": args.max_blocks,
                    "max_logs": args.max_logs,
                    "max_buckets": args.max_buckets,
                    "metadata_sha256": args.metadata_digest,
                    "abi_revision": ABI_REVISION,
                    "request_fingerprint": {
                        "market_ids": sorted(args.market),
                        "exchange": exchange,
                        "from_block": args.from_block,
                        "to_block": args.to_block,
                    },
                }
            )
            return {
                "plan_id": plan_id,
                "rpc_calls": rpc.calls,
                "http_attempts": client.requests,
                "downloaded_bytes": client.downloaded,
                "estimated_minute_buckets": estimated,
            }
    store = Store(args.root, CONTRACT)
    if args.command == "scan":
        plan = store.load_plan(args.plan)
        client, rpc = rpc_client(store, Limits.from_dict(plan["limits"]))
        with client:
            acquisition = scan(
                store,
                args.plan,
                rpc,
                args.resume,
                on_started=lambda value: print(
                    json.dumps({"acquisition_id": value, "status": "started"}),
                    file=sys.stderr,
                    flush=True,
                ),
            )
        return {
            "acquisition_id": acquisition,
            "http_attempts": client.requests,
            "rpc_calls": rpc.calls,
            "downloaded_bytes": client.downloaded,
        }
    if args.command == "build":
        return {"release_id": build(store, args.plan, args.acquisition)}
    if args.command == "publish":
        return publish(store, args.release)
    if args.command == "verify":
        result = store.verify(args.release)
        if args.live:
            # Live verification is bounded independently of the acquisition plan.
            limits = Limits(args.max_requests, 256 * 1024**2, 1024**3, 16 * 1024**2, 256 * 1024**2)
            client, rpc = rpc_client(store, limits)
            with client:
                result = {"offline": result, **live_verify(store, rpc, args.release)}
        return result
    if args.command == "published-legs":
        return {"economic_legs": published_legs(store, args.max_temp_bytes)}
    if args.command == "status":
        return {
            **store.status(),
            "acquisition_inventory": [
                store.acquisition(directory.name)
                for directory in (store.root / "acquisitions").iterdir()
            ],
            "invalidations": [
                path.name for path in (store.root / "published").glob("*.invalid.json")
            ],
        }
    raise PolygonError("Unknown command")


def main(argv=None) -> int:
    args = parser().parse_args(argv)
    try:
        value = run(args)
    except (PolygonError, SourceError, BudgetExceeded) as exc:
        print(json.dumps({"error": "command_failed", "message": str(exc)}), file=sys.stderr)
        return 1
    except (ValueError, Timeout, OSError):
        # Arbitrary input/path exception text may include credentials.
        print(
            json.dumps(
                {
                    "error": "command_failed",
                    "hint": "Check root ownership, input contracts, and acquisition status.",
                }
            ),
            file=sys.stderr,
        )
        return 1
    print(json_bytes(value).decode())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
