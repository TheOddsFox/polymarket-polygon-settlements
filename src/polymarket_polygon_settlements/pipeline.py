"""Finite scans and offline projections over committed sanitized evidence."""

import re
import tempfile
from dataclasses import asdict

import duckdb
import pyarrow as pa
import pyarrow.parquet as pq

from .codec import ABI_REVISION, Event, PolygonError, quantity
from .foundation import (
    BudgetExceeded,
    Limits,
    Store,
    atomic_write,
    digest,
    fsync_dir,
    json_bytes,
    read_bytes,
    read_json,
    verify_directory,
)
from .metadata import load_metadata
from .normalize import (
    NORMALIZER_VERSION,
    Target,
    deduplicate_legs,
    minute_aggregates,
    normalize_events,
)
from .rpc import RPC, adaptive_leaves

CONTRACT = "oddsfox.polymarket.polygon-settlements.v1"
EVENT_SCHEMA = pa.schema(
    [
        (
            field,
            pa.string()
            if field
            in {
                "kind",
                "exchange_address",
                "block_hash",
                "transaction_hash",
                "side",
                "token_id",
                "maker_amount",
                "taker_amount",
            }
            else pa.int64(),
        )
        for field in Event.__dataclass_fields__
    ]
)
LEG_SCHEMA = pa.schema(
    [
        ("venue", pa.string()),
        ("collateral_address", pa.string()),
        ("ctf_collateral_address", pa.string()),
        ("collateral_decimals", pa.int64()),
        ("chain_id", pa.int64()),
        ("exchange_address", pa.string()),
        ("block_number", pa.int64()),
        ("block_hash", pa.string()),
        ("block_timestamp", pa.int64()),
        ("transaction_hash", pa.string()),
        ("transaction_index", pa.int64()),
        ("passive_log_index", pa.int64()),
        ("active_log_index", pa.int64()),
        ("matched_log_index", pa.int64()),
        ("leg_ordinal", pa.int64()),
        ("market_id", pa.string()),
        ("condition_id", pa.string()),
        ("asset_kind", pa.string()),
        ("asset_id", pa.string()),
        ("index_set", pa.int64()),
        ("order_side", pa.string()),
        ("source_token_id", pa.string()),
        ("source_maker_amount_raw", pa.string()),
        ("source_taker_amount_raw", pa.string()),
        ("share_amount_raw", pa.string()),
        ("collateral_amount_raw", pa.string()),
        ("share_volume", pa.decimal128(38, 6)),
        ("gross_collateral_volume", pa.decimal128(38, 6)),
        ("price", pa.decimal128(38, 18)),
        ("normalization_kind", pa.string()),
        ("is_derived", pa.bool_()),
        ("segment_sha256", pa.string()),
        ("normalizer_version", pa.string()),
    ]
)
MINUTE_SCHEMA = pa.schema(
    [
        ("venue", pa.string()),
        ("collateral_address", pa.string()),
        ("ctf_collateral_address", pa.string()),
        ("collateral_decimals", pa.int64()),
        ("market_id", pa.string()),
        ("condition_id", pa.string()),
        ("exchange_address", pa.string()),
        ("asset_kind", pa.string()),
        ("asset_id", pa.string()),
        ("minute_timestamp", pa.int64()),
        ("minute_utc", pa.string()),
        ("coverage", pa.string()),
        ("observed_leg_count", pa.int64()),
        ("leg_count", pa.int64()),
        ("share_volume", pa.decimal128(38, 6)),
        ("gross_collateral_volume", pa.decimal128(38, 6)),
        *[(name, pa.decimal128(38, 18)) for name in ("vwap", "open", "high", "low", "close")],
    ]
)


def target_objects(plan: dict) -> list[Target]:
    return [Target(**row) for row in plan["targets"]]


def _invalid_acquisition(store: Store, acquisition_id: str) -> bool:
    return (store.root / "acquisitions" / acquisition_id / "invalid.json").exists()


def _invalidate_hash(
    store: Store, number: int, expected_hash: str, known_plan_id: str, known_captures: list[dict]
):
    affected_captures, affected_plans, corrupt = set(), {known_plan_id}, []

    def withdraw_plan(plan_id):
        atomic_write(
            store.root / ".state" / (plan_id + ".invalid.json"),
            json_bytes({"reason": "finalized_header_mismatch", "block_number": number}),
        )
        pointer = store.root / "published" / (plan_id + ".current.json")
        if pointer.exists():
            try:
                release_id = read_json(pointer).get("release_id")
                if re.fullmatch(r"[0-9a-f]{64}", release_id or ""):
                    atomic_write(
                        store.root / "published" / (release_id + ".invalid.json"),
                        json_bytes({"reason": "finalized_header_mismatch", "block_number": number}),
                    )
            except (ValueError, OSError):
                corrupt.append(plan_id)
            finally:
                pointer.unlink(missing_ok=True)
                fsync_dir(pointer.parent)

    # A verified mismatch must withdraw its known pointer before unrelated I/O.
    withdraw_plan(known_plan_id)
    for capture in known_captures:
        atomic_write(
            store.root / "acquisitions" / capture["acquisition_id"] / "invalid.json",
            json_bytes({"reason": "finalized_header_mismatch", "block_number": number}),
        )
    for acquisition in (store.root / "acquisitions").iterdir():
        try:
            directories = list((acquisition / "captures").iterdir())
        except OSError:
            corrupt.append(acquisition.name)
            continue
        for directory in directories:
            if directory.name.startswith(".pending-"):
                continue
            try:
                capture = verify_directory(directory)
                evidence = store.read_evidence(capture)
                if any(
                    header["number"] == number and header["hash"] == expected_hash
                    for header in evidence.get("headers", [])
                ):
                    affected_captures.add(capture["capture_id"])
                    affected_plans.add(capture["plan_id"])
                    atomic_write(
                        acquisition / "invalid.json",
                        json_bytes({"reason": "finalized_header_mismatch", "block_number": number}),
                    )
            except (ValueError, OSError, KeyError):
                corrupt.append(directory.name)
    for path in (store.root / "plans").glob("*.json"):
        try:
            plan = store.load_plan(path.stem)
            if any(
                header["number"] == number and header["hash"] == expected_hash
                for header in plan.get("headers", [])
            ):
                affected_plans.add(path.stem)
        except (ValueError, OSError, KeyError):
            corrupt.append(path.name)
    for plan_id in affected_plans - {known_plan_id}:
        withdraw_plan(plan_id)
    for directory in (store.root / "published").iterdir():
        if not directory.is_dir() or directory.name.startswith(".pending-"):
            continue
        try:
            manifest = store.verify(directory.name)
            if manifest["plan_id"] in affected_plans or set(manifest["inputs"]) & affected_captures:
                atomic_write(
                    store.root / "published" / (directory.name + ".invalid.json"),
                    json_bytes({"reason": "finalized_header_mismatch", "block_number": number}),
                )
        except (ValueError, OSError, KeyError):
            corrupt.append(directory.name)
    if corrupt:
        atomic_write(
            store.root / ".state" / "header_mismatch_corruption.json",
            json_bytes(
                {
                    "reason": "corrupt_evidence_during_invalidation",
                    "block_number": number,
                    "local_ids": sorted(set(corrupt)),
                }
            ),
        )
    return bool(corrupt)


def revalidate(store: Store, plan: dict, rpc: RPC, captures: list[dict]):
    if (store.root / ".state" / (plan["plan_id"] + ".invalid.json")).exists():
        raise PolygonError("Plan was invalidated; create a new finalized plan")
    if any(_invalid_acquisition(store, capture["acquisition_id"]) for capture in captures):
        raise PolygonError("Acquisition was invalidated")
    expected = {}
    for header in [
        *plan["headers"],
        *(header for capture in captures for header in store.read_evidence(capture)["headers"]),
    ]:
        if header["number"] in expected and expected[header["number"]] != header["hash"]:
            raise PolygonError("Committed headers disagree")
        expected[header["number"]] = header["hash"]
    if quantity(rpc.call("eth_chainId", [])) != 137:
        raise PolygonError("RPC chain must be Polygon 137")
    head = rpc.block("finalized")
    if head.number < plan["to_block"]:
        raise PolygonError("RPC finality regressed below requested interval")
    for number, block_hash in expected.items():
        if rpc.block(number).hash != block_hash:
            corrupt = _invalidate_hash(store, number, block_hash, plan["plan_id"], captures)
            suffix = "; unrelated corruption recorded" if corrupt else ""
            raise PolygonError(
                "Finalized header mismatch; affected publications withdrawn" + suffix
            )


def _gaps(start: int, end: int, ranges: list[tuple[int, int]]) -> list[tuple[int, int]]:
    cursor, result = start, []
    for left, right in sorted(ranges):
        if left < start or right > end or right < left:
            raise PolygonError("Capture range outside sealed plan")
        if left > cursor:
            result.append((cursor, left - 1))
        cursor = max(cursor, right + 1)
    if cursor <= end:
        result.append((cursor, end))
    return result


def scan(
    store: Store, plan_id: str, rpc: RPC, resume_id: str | None = None, on_started=None
) -> str:
    with store.lock:
        plan = {**store.load_plan(plan_id), "plan_id": plan_id}
        load_metadata(store.root / "inputs" / plan["metadata_sha256"], plan["metadata_sha256"])
        existing = store.committed_captures(acquisition_id=resume_id) if resume_id else []
        # Revalidation happens before any resume skip or new network collection.
        revalidate(store, plan, rpc, existing)
        acquisition_id = store.new_acquisition(plan_id, "polygon_ctf_exchange_v2", resume_id)
        if _invalid_acquisition(store, acquisition_id):
            raise PolygonError("Acquisition was invalidated")
        if on_started:
            on_started(acquisition_id)
        targets = target_objects(plan)
        for exchange in sorted({target.exchange_address for target in targets}):
            scoped = [target for target in targets if target.exchange_address == exchange]
            covered = [
                (entry["from_block"], entry["to_block"])
                for capture in existing
                for entry in capture["coverage"]
                if entry["exchange_address"] == exchange
                and entry["status"] in {"success", "confirmed_empty"}
            ]
            for start, end in _gaps(plan["from_block"], plan["to_block"], covered):
                for left, right, events, legs, headers in adaptive_leaves(
                    rpc, exchange, start, end, scoped, max_logs=plan["max_logs"]
                ):
                    if any(
                        header["number"] > plan["finalized_head"]["number"] for header in headers
                    ):
                        raise PolygonError("Capture crossed pinned finalized head")
                    store.capture(
                        acquisition_id,
                        f"{exchange}_{left}_{right}",
                        {"sanitized_events": events},
                        evidence={
                            "headers": headers,
                            "abi_revision": ABI_REVISION,
                            "normalizer_version": NORMALIZER_VERSION,
                            "target_proofs": [asdict(target) for target in scoped],
                        },
                        coverage=[
                            {
                                "exchange_address": exchange,
                                "from_block": left,
                                "to_block": right,
                                "status": "success" if legs else "confirmed_empty",
                                "economic_leg_count": len(legs),
                            }
                        ],
                        schemas={"sanitized_events": EVENT_SCHEMA},
                    )
        revalidate(store, plan, rpc, store.committed_captures(acquisition_id=acquisition_id))
        return acquisition_id


def build(store: Store, plan_id: str, acquisition_ids: list[str]) -> str:
    with store.lock:
        plan = store.load_plan(plan_id)
        store.limits = Limits.from_dict(plan["limits"])
        load_metadata(store.root / "inputs" / plan["metadata_sha256"], plan["metadata_sha256"])
        if (store.root / ".state" / (plan_id + ".invalid.json")).exists():
            raise PolygonError("Plan was invalidated")
        if not acquisition_ids or len(set(acquisition_ids)) != len(acquisition_ids):
            raise PolygonError("Explicit unique acquisition inventory required")
        captures = []
        for acquisition in acquisition_ids:
            if _invalid_acquisition(store, acquisition):
                raise PolygonError("Acquisition was invalidated")
            descriptor = store.acquisition(acquisition)
            if (
                descriptor["plan_id"] != plan_id
                or descriptor["source"] != "polygon_ctf_exchange_v2"
            ):
                raise PolygonError("Acquisition does not belong to this plan/source")
            captures.extend(store.committed_captures(acquisition_id=acquisition))
        targets = target_objects(plan)
        _preflight_build(store, plan, captures, targets)
        coverage = [row for capture in captures for row in capture["coverage"]]
        for exchange in {target.exchange_address for target in targets}:
            ranges = [
                (row["from_block"], row["to_block"])
                for row in coverage
                if row["exchange_address"] == exchange
                and row["status"] in {"success", "confirmed_empty"}
            ]
            if _gaps(plan["from_block"], plan["to_block"], ranges):
                raise PolygonError("Unfinished block coverage cannot publish")
        headers, by_event = {}, {}
        for capture in captures:
            evidence = store.read_evidence(capture)
            if (
                evidence["abi_revision"] != ABI_REVISION
                or evidence["normalizer_version"] != NORMALIZER_VERSION
            ):
                raise PolygonError("Unsupported capture decoder/normalizer revision")
            for header in evidence["headers"]:
                if header["number"] in headers and headers[header["number"]] != header:
                    raise PolygonError("Conflicting block headers")
                headers[header["number"]] = header
            for value in store.read_relation(capture, "sanitized_events"):
                event = Event.from_sanitized(value)
                key = (event.exchange_address, event.transaction_hash, event.log_index)
                if key in by_event and by_event[key] != event:
                    raise PolygonError("Conflicting sanitized event identity")
                by_event[key] = event
        events = list(by_event.values())
        if any(
            event.block_number not in headers
            or headers[event.block_number]["hash"] != event.block_hash
            for event in events
        ):
            raise PolygonError("Sanitized event lacks finalized header")
        legs = deduplicate_legs(
            normalize_events(
                events, targets, {number: header["timestamp"] for number, header in headers.items()}
            )
        )
        minutes = minute_aggregates(
            legs,
            targets,
            plan["start_timestamp"],
            plan["end_timestamp_exclusive"],
            plan["max_buckets"],
            plan["end_boundary_confirmed"],
        )
        relations = {
            "sanitized_events": [
                event.sanitized()
                for event in sorted(
                    events,
                    key=lambda event: (
                        event.block_number,
                        event.transaction_index,
                        event.log_index,
                    ),
                )
            ],
            "economic_legs": legs,
            "minute_aggregates": minutes,
        }
        return store.build_release(
            plan_id,
            captures,
            relations,
            coverage,
            schemas={
                "sanitized_events": EVENT_SCHEMA,
                "economic_legs": LEG_SCHEMA,
                "minute_aggregates": MINUTE_SCHEMA,
            },
            versions={"schema": 1, "normalizer": NORMALIZER_VERSION, "abi_revision": ABI_REVISION},
        )


def live_verify(store: Store, rpc: RPC, release_id: str | None = None):
    with store.lock:
        releases = [release_id] if release_id else store.verify()["releases"]
        for release in releases:
            manifest = store.verify(release)
            plan = {**store.load_plan(manifest["plan_id"]), "plan_id": manifest["plan_id"]}
            inputs = {
                capture["capture_id"]: capture
                for capture in store.committed_captures(plan_id=manifest["plan_id"])
            }
            revalidate(store, plan, rpc, [inputs[capture_id] for capture_id in manifest["inputs"]])
        return {"live_verified_releases": len(releases), "rpc_calls": rpc.calls}


def _parquet_footprint(path, *, expected_schema=None):
    parquet = pq.ParquetFile(path)
    try:
        if expected_schema is not None and not parquet.schema_arrow.equals(expected_schema):
            raise PolygonError("Unexpected economic relation schema")
        metadata = parquet.metadata
        uncompressed = sum(
            metadata.row_group(group).column(column).total_uncompressed_size
            for group in range(metadata.num_row_groups)
            for column in range(metadata.num_columns)
        )
        return metadata.num_rows, uncompressed
    finally:
        parquet.close()


def _preflight_build(store: Store, plan: dict, captures: list[dict], targets: list[Target]):
    # Conservative Python/Arrow/derived-leg overhead is checked before row decoding.
    projected = 0
    for capture in captures:
        rows, size = _parquet_footprint(
            store.capture_path(capture) / "sanitized_events.parquet", expected_schema=EVENT_SCHEMA
        )
        projected += (
            size * 8
            + rows * 32 * 1024
            + sum(item["size"] for item in capture["files"].values()) * 8
        )
    minutes = (
        (plan["end_timestamp_exclusive"] - 1) // 60 - plan["start_timestamp"] // 60 + 1
    ) * sum(len(target.tokens) for target in targets)
    if minutes > plan["max_buckets"]:
        raise BudgetExceeded("aggregate bucket budget exhausted")
    projected += minutes * 16 * 1024
    if projected > store.limits.max_temp_bytes:
        raise BudgetExceeded("decoded capture/derived output working-set budget exhausted")


def published_legs(
    store: Store, max_temp_bytes: int, candidate_release: str | None = None
) -> list[dict]:
    """Bounded canonical economic union of verified active plan publications."""
    if type(max_temp_bytes) is not int or max_temp_bytes < 2 * 1024**2:
        raise BudgetExceeded("canonical query requires at least 2 MiB of explicit working budget")
    with store.lock:
        candidate = store.verify(candidate_release) if candidate_release else None
        manifests = []
        for pointer_path in sorted((store.root / "published").glob("*.current.json")):
            # A candidate atomically supersedes this plan's previous pointer.
            if candidate and pointer_path.name == candidate["plan_id"] + ".current.json":
                continue
            pointer = read_json(pointer_path)
            if (
                not isinstance(pointer, dict)
                or set(pointer) != {"release_id", "manifest_sha256"}
                or any(
                    not isinstance(pointer[field], str)
                    or not re.fullmatch(r"[0-9a-f]{64}", pointer[field])
                    for field in pointer
                )
            ):
                raise PolygonError("Malformed active publication pointer")
            release_id = pointer["release_id"]
            manifest = store.verify(release_id)
            raw = read_bytes(store.root / "published" / release_id / "manifest.json")
            if pointer_path.name != manifest["plan_id"] + ".current.json" or digest(
                raw
            ) != pointer.get("manifest_sha256"):
                raise PolygonError("Active publication pointer integrity mismatch")
            if (store.root / "published" / (release_id + ".invalid.json")).exists():
                raise PolygonError("Active publication is invalidated")
            if (store.root / ".state" / (manifest["plan_id"] + ".invalid.json")).exists():
                raise PolygonError("Active publication plan is invalidated")
            manifests.append(manifest)
        if candidate:
            if (store.root / "published" / (candidate_release + ".invalid.json")).exists():
                raise PolygonError("Candidate publication is invalidated")
            if (store.root / ".state" / (candidate["plan_id"] + ".invalid.json")).exists():
                raise PolygonError("Candidate publication plan is invalidated")
            manifests.append(candidate)
        if not manifests:
            return []
        paths, projected = [], 0
        for manifest in manifests:
            path = store.root / "published" / manifest["release_id"] / "economic_legs.parquet"
            rows, size = _parquet_footprint(path, expected_schema=LEG_SCHEMA)
            projected += size * 8 + rows * 32 * 1024
            paths.append(str(path))
        if projected > max_temp_bytes:
            raise BudgetExceeded("canonical economic union working-set budget exhausted")
        # Fixed SQL and bound paths prevent metadata-derived SQL execution.
        with tempfile.TemporaryDirectory(
            prefix="canonical-legs-", dir=store.root / ".state"
        ) as temporary:
            half = max_temp_bytes // 2
            connection = duckdb.connect(
                config={
                    "memory_limit": f"{half}B",
                    "max_temp_directory_size": f"{half}B",
                    "temp_directory": temporary,
                    "threads": "1",
                }
            )
            try:
                connection.execute(
                    "CREATE TEMP TABLE legs AS SELECT * FROM read_parquet(?)", [paths]
                )
                conflict = connection.execute(
                    """SELECT 1 FROM legs GROUP BY chain_id, exchange_address, block_hash, transaction_hash, passive_log_index, leg_ordinal HAVING COUNT(DISTINCT to_json(legs)) > 1 LIMIT 1"""
                ).fetchone()
                if conflict:
                    raise PolygonError("Conflicting economic leg identity across active plans")
                cursor = connection.execute(
                    "SELECT DISTINCT * FROM legs ORDER BY block_number, transaction_index, passive_log_index, leg_ordinal, exchange_address"
                )
                columns = [column[0] for column in cursor.description]
                return [dict(zip(columns, row, strict=True)) for row in cursor.fetchall()]
            except duckdb.Error:
                raise BudgetExceeded("bounded canonical economic query failed") from None
            finally:
                connection.close()


def publish(store: Store, release_id: str):
    """Validate the root-wide economic union before advancing a plan pointer."""
    with store.lock:
        manifest = store.verify(release_id)
        plan = store.load_plan(manifest["plan_id"])
        store.limits = Limits.from_dict(plan["limits"])
        if (store.root / ".state" / (manifest["plan_id"] + ".invalid.json")).exists():
            raise PolygonError("Plan was invalidated")
        published_legs(store, store.limits.max_temp_bytes, candidate_release=release_id)
        return store.publish(release_id)
