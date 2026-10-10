"""Offline synthetic and audited-normalizer regression scenarios."""

import hashlib
import json
from dataclasses import replace
from decimal import Decimal

import pytest

from polymarket_polygon_settlements.codec import (
    CTF,
    ORDER_FILLED_TOPIC,
    ORDERS_MATCHED_TOPIC,
    STANDARD_EXCHANGE,
    Event,
    PolygonError,
    decode_log,
)
from polymarket_polygon_settlements.foundation import Limits, Store, digest, json_bytes
from polymarket_polygon_settlements.metadata import pin_metadata
from polymarket_polygon_settlements.normalize import (
    Target,
    deduplicate_legs,
    minute_aggregates,
    normalize_segment,
    price,
)
from polymarket_polygon_settlements.pipeline import CONTRACT, build, live_verify, scan
from polymarket_polygon_settlements.rpc import RPC, finalized_plan

CONDITION = "0x" + "a" * 64
COLLATERAL = "0x" + "b" * 40
BLOCK_HASH = "0x" + "1" * 64
TX = "0x" + "2" * 64
TARGET = Target("1", CONDITION, STANDARD_EXCHANGE, {"11": 1, "12": 2}, COLLATERAL, COLLATERAL)
LIMITS = Limits(1000, 16 * 1024**2, 128 * 1024**2, 8 * 1024**2, 16 * 1024**2)


def event(kind, side, token, maker, taker, index):
    return Event(kind, STANDARD_EXCHANGE, 100, BLOCK_HASH, TX, 0, index, side, token, maker, taker)


def raw_log(kind="order_filled", side=1, token=11, maker=1_000_000, taker=600_000, index=1):
    words = [side, token, maker, taker] + ([0, 0, 0] if kind == "order_filled" else [])
    return {
        "address": STANDARD_EXCHANGE,
        "blockNumber": "0x64",
        "blockHash": BLOCK_HASH,
        "transactionHash": TX,
        "transactionIndex": "0x0",
        "logIndex": hex(index),
        "removed": False,
        "topics": [
            ORDER_FILLED_TOPIC if kind == "order_filled" else ORDERS_MATCHED_TOPIC,
            "0x" + "3" * 64,
            "0x" + "4" * 64,
            *(["0x" + "5" * 64] if kind == "order_filled" else []),
        ],
        "data": "0x" + "".join(f"{word:064x}" for word in words),
    }


def normalize(passive, active, matched):
    return normalize_segment(passive, active, matched, [TARGET], 6000)


def test_complementary_does_not_count_active_aggregate():
    rows = normalize(
        [event("order_filled", "SELL", "11", 1_000_000, 600_000, 1)],
        event("order_filled", "BUY", "11", 600_000, 1_000_000, 2),
        event("orders_matched", "BUY", "11", 600_000, 1_000_000, 3),
    )
    assert len(rows) == 1
    assert rows[0]["price"] == Decimal("0.600000000000000000")
    assert rows[0]["share_volume"] == Decimal("1.000000")
    assert rows[0]["source_maker_amount_raw"] == "1000000"
    assert rows[0]["index_set"] == 1


@pytest.mark.parametrize(
    "side,kind,active_amounts,passive_amounts",
    [
        ("BUY", "mint", (1_800_000, 3_000_000), [(400_000, 1_000_000), (800_000, 2_000_000)]),
        ("SELL", "merge", (3_000_000, 1_800_000), [(1_000_000, 400_000), (2_000_000, 800_000)]),
    ],
)
def test_multimaker_mint_merge(side, kind, active_amounts, passive_amounts):
    passive = [
        event("order_filled", side, "12", maker, taker, i)
        for i, (maker, taker) in enumerate(passive_amounts, 1)
    ]
    rows = normalize(
        passive,
        event("order_filled", side, "11", *active_amounts, 3),
        event("orders_matched", side, "11", *active_amounts, 4),
    )
    assert len(rows) == 4
    assert {row["normalization_kind"] for row in rows} == {kind}
    assert [row["leg_ordinal"] for row in rows] == [0, 1, 0, 1]
    assert {row["price"] for row in rows if row["is_derived"]} == {Decimal("0.600000000000000000")}


@pytest.mark.parametrize(
    "side,passive,amounts",
    [
        (
            "BUY",
            [("SELL", "11", 1_000_000, 600_000), ("BUY", "12", 400_000, 1_000_000)],
            (1_200_000, 2_000_000),
        ),
        (
            "SELL",
            [("BUY", "11", 600_000, 1_000_000), ("SELL", "12", 1_000_000, 400_000)],
            (2_000_000, 1_200_000),
        ),
    ],
)
def test_mixed_matches_accept_refund_only_in_maker_dimension(side, passive, amounts):
    makers = [
        event("order_filled", maker_side, token, maker, taker, i)
        for i, (maker_side, token, maker, taker) in enumerate(passive, 1)
    ]
    active = event("order_filled", side, "11", *amounts, 3)
    matched = event("orders_matched", side, "11", *amounts, 4)
    assert len(normalize(makers, active, matched)) == 3
    assert (
        len(
            normalize(
                makers,
                replace(active, maker_amount=active.maker_amount + 123),
                replace(matched, maker_amount=matched.maker_amount + 123),
            )
        )
        == 3
    )
    with pytest.raises(PolygonError, match="conserve"):
        normalize(
            makers,
            replace(active, taker_amount=active.taker_amount + 1),
            replace(matched, taker_amount=matched.taker_amount + 1),
        )


def test_one_micro_collateral_refund_regression():
    passive = [
        event("order_filled", "BUY", "12", maker, taker, i)
        for i, (maker, taker) in enumerate(
            [(3_836_160, 3_840_000), (9_930_000, 10_000_000), (101_980_506, 102_906_665)], 1
        )
    ]
    active = event("order_filled", "BUY", "11", 1_000_000, 116_746_665, 4)
    matched = event("orders_matched", "BUY", "11", 1_000_000, 116_746_665, 5)
    rows = normalize(passive, active, matched)
    assert sum(int(row["collateral_amount_raw"]) for row in rows if row["is_derived"]) == 999_999
    with pytest.raises(PolygonError, match="conserve"):
        normalize(
            passive, replace(active, maker_amount=999_998), replace(matched, maker_amount=999_998)
        )


@pytest.mark.parametrize(
    "cash,shares,expected",
    [
        (1, 7, "0.142857142857142857"),
        (4, 7, "0.571428571428571429"),
        (1, 524_288, "0.000001907348632812"),
        (3, 524_288, "0.000005722045898438"),
    ],
)
def test_integer_ratio_half_even(cash, shares, expected):
    assert price(cash, shares) == Decimal(expected)


def test_decoder_never_retains_wallets_order_hashes_or_topics():
    raw = raw_log()
    raw["provider_url"] = "https://rpc.invalid/SECRET"
    row = decode_log(raw).sanitized()
    assert "SECRET" not in json.dumps(row)
    assert not {"topics", "data", "maker", "taker", "order_hash", "provider_url"} & row.keys()
    with pytest.raises(PolygonError):
        decode_log({**raw, "removed": True})
    with pytest.raises(PolygonError):
        decode_log({**raw, "data": raw["data"][:-64]})


def test_natural_leg_key_deduplicates_overlap_and_rejects_conflicts():
    rows = normalize(
        [event("order_filled", "SELL", "11", 1_000_000, 600_000, 1)],
        event("order_filled", "BUY", "11", 600_000, 1_000_000, 2),
        event("orders_matched", "BUY", "11", 600_000, 1_000_000, 3),
    )
    assert len(deduplicate_legs(rows + rows)) == 1
    with pytest.raises(PolygonError, match="Conflicting"):
        deduplicate_legs(rows + [{**rows[0], "price": Decimal("0.7")}])


def test_minutes_zero_only_for_full_coverage_and_exact_vwap():
    rows = normalize(
        [event("order_filled", "SELL", "11", 1_000_000, 600_000, 1)],
        event("order_filled", "BUY", "11", 600_000, 1_000_000, 2),
        event("orders_matched", "BUY", "11", 600_000, 1_000_000, 3),
    )
    complete = minute_aggregates(rows, [TARGET], 6000, 6120)
    assert complete[0]["vwap"] == Decimal("0.6")
    assert complete[1]["leg_count"] == 0
    assert complete[1]["share_volume"] == Decimal("0")
    assert complete[1]["vwap"] is None
    partial = minute_aggregates([], [TARGET], 6001, 6059)
    assert partial[0]["leg_count"] is None
    assert partial[0]["share_volume"] is None
    head_boundary = minute_aggregates([], [TARGET], 6000, 6060, end_boundary_confirmed=False)
    assert head_boundary[0]["coverage"] == "partial_boundary"


class FakeChain:
    def __init__(self, *, empty=False):
        self.calls = []
        self.selectors = {}
        self.empty = empty
        self.split = False
        self.changed = set()
        self.missing_receipt = False

    def __call__(self, body):
        method, params = body["method"], body["params"]
        self.calls.append((method, params))
        if method == "eth_chainId":
            value = "0x89"
        elif method == "web3_sha3":
            signature = bytes.fromhex(params[0][2:]).decode()
            value = "0x" + hashlib.sha256(signature.encode()).hexdigest()
            self.selectors[value[2:10]] = signature
        elif method == "eth_getCode":
            value = "0x1234"
        elif method == "eth_call":
            data, contract = params[0]["data"], params[0]["to"]
            signature = self.selectors[data[2:10]]
            if signature == "getCtf()":
                integer = int(CTF, 16)
            elif signature in {"getCollateral()", "getCtfCollateral()", "getOutcomeTokenFactory()"}:
                integer = int(COLLATERAL, 16)
            elif signature == "decimals()":
                integer = 6
            elif signature == "getOutcomeSlotCount(bytes32)":
                integer = 2
            elif signature.startswith("getCollectionId"):
                integer = int(data[-64:], 16)
            elif signature.startswith("getPositionId"):
                integer = int(data[-64:], 16) + 10
            else:
                raise AssertionError((signature, contract))
            value = "0x" + f"{integer:064x}"
        elif method == "eth_getBlockByNumber":
            number = 110 if params[0] == "finalized" else int(params[0], 16)
            block_hash = "0x" + ("9" if number in self.changed else "1") * 64
            value = {
                "number": hex(number),
                "hash": block_hash,
                "timestamp": hex(6000 + (number - 100) * 60),
            }
        elif method == "eth_getLogs":
            left, right = int(params[0]["fromBlock"], 16), int(params[0]["toBlock"], 16)
            if self.split and left < right:
                return {
                    "jsonrpc": "2.0",
                    "id": body["id"],
                    "error": {"code": -32005, "message": "too many results SECRET"},
                }
            value = (
                []
                if self.empty or not left <= 100 <= right
                else [raw_log("orders_matched", 0, 11, 600_000, 1_000_000, 3)]
            )
        elif method == "eth_getTransactionReceipt":
            value = (
                None
                if self.missing_receipt
                else {
                    "transactionHash": TX,
                    "blockNumber": "0x64",
                    "blockHash": BLOCK_HASH,
                    "transactionIndex": "0x0",
                    "status": "0x1",
                    "logs": [
                        raw_log(),
                        raw_log("order_filled", 0, 11, 600_000, 1_000_000, 2),
                        raw_log("orders_matched", 0, 11, 600_000, 1_000_000, 3),
                    ],
                }
            )
        else:
            raise AssertionError(method)
        return {"jsonrpc": "2.0", "id": body["id"], "result": value}


def metadata(tmp_path):
    directory = tmp_path / "metadata"
    directory.mkdir()
    markets = [{"venue": "polymarket", "market_id": "1", "condition_id": CONDITION}]
    outcomes = [
        {
            "venue": "polymarket",
            "market_id": "1",
            "condition_id": CONDITION,
            "outcome_index": ordinal,
            "asset_kind": "ctf_token",
            "asset_id": token,
            "clob_token_id": token,
            "position_id": None,
        }
        for ordinal, token in enumerate(("12", "11"), 1)
    ]
    relations = {
        "markets": markets,
        "outcomes": outcomes,
        "memberships": [],
        "identity_history": [],
        "coverage": [{"market_id": "1", "status": "found"}],
    }
    files = {}
    for name, rows in relations.items():
        raw = json_bytes(rows)
        (directory / (name + ".json")).write_bytes(raw)
        files[name + ".json"] = {"size": len(raw), "sha256": digest(raw)}
    raw = json_bytes({"contract": "oddsfox.polymarket.metadata.v1", "files": files})
    (directory / "manifest.json").write_bytes(raw)
    return directory, digest(raw), markets, outcomes


def prepared(tmp_path, chain=None):
    chain = chain or FakeChain()
    store = Store(tmp_path / "data", CONTRACT, LIMITS)
    directory, sha, markets, outcomes = metadata(tmp_path)
    pin_metadata(store.root, directory, sha)
    plan = finalized_plan(RPC(chain), markets, outcomes, ["1"], [STANDARD_EXCHANGE], 100, 102)
    plan_id = store.create_plan(
        {
            **plan,
            "metadata_sha256": sha,
            "limits": LIMITS.as_dict(),
            "max_logs": 100,
            "max_buckets": 100,
        }
    )
    return store, plan_id, chain


def test_proof_uses_chain_index_sets_not_metadata_ordinal(tmp_path):
    store, plan_id, _ = prepared(tmp_path)
    assert store.load_plan(plan_id)["targets"][0]["token_index_sets"] == {"11": 1, "12": 2}


def test_position_rejected_before_any_rpc():
    chain = FakeChain()
    with pytest.raises(PolygonError, match="before RPC"):
        finalized_plan(
            RPC(chain),
            [{"market_id": "1"}],
            [{"market_id": "1", "asset_kind": "poly_v2_position"}],
            ["1"],
            [STANDARD_EXCHANGE],
            100,
            102,
        )
    assert not chain.calls


def test_unfinalized_range_is_not_clipped(tmp_path):
    chain = FakeChain()
    _, _, markets, outcomes = metadata(tmp_path)
    with pytest.raises(PolygonError, match="finalized"):
        finalized_plan(RPC(chain), markets, outcomes, ["1"], [STANDARD_EXCHANGE], 100, 111)


def test_chain_targets_reject_wrong_pair(tmp_path):
    _, _, markets, outcomes = metadata(tmp_path)
    outcomes[0]["asset_id"] = "999"
    with pytest.raises(PolygonError, match="validation rule"):
        finalized_plan(RPC(FakeChain()), markets, outcomes, ["1"], [STANDARD_EXCHANGE], 100, 102)


def test_end_to_end_offline_scan_replay_overlap_and_publication(tmp_path):
    store, plan, chain = prepared(tmp_path)
    acquisition = scan(store, plan, RPC(chain))
    release = build(store, plan, [acquisition])
    store.publish(release)
    assert store.verify(release)["capture_complete"] is True
    assert build(store, plan, [acquisition]) == release
    again = scan(store, plan, RPC(chain))
    combined = build(store, plan, [acquisition, again])
    import pyarrow.parquet as pq

    assert (
        pq.read_table(store.root / "published" / combined / "economic_legs.parquet").num_rows == 1
    )
    retained = json.dumps(
        store.read_evidence(store.committed_captures(acquisition_id=acquisition)[0])
    )
    assert "topics" not in retained and "maker_address" not in retained


def test_provider_range_split_and_resume_skip_completed_leaves(tmp_path):
    store, plan, chain = prepared(tmp_path)
    chain.split = True
    acquisition = scan(store, plan, RPC(chain))
    assert len(store.committed_captures(acquisition_id=acquisition)) == 3
    chain.calls.clear()
    assert scan(store, plan, RPC(chain), acquisition) == acquisition
    assert not any(method == "eth_getLogs" for method, _ in chain.calls)


def test_missing_receipt_cannot_build_or_publish(tmp_path):
    store, plan, chain = prepared(tmp_path)
    chain.missing_receipt = True
    started = []
    with pytest.raises(PolygonError, match="receipt"):
        scan(store, plan, RPC(chain), on_started=started.append)
    with pytest.raises(PolygonError, match="Unfinished"):
        build(store, plan, started)


def test_confirmed_empty_publishes_typed_empty_economic_table(tmp_path):
    store, plan, chain = prepared(tmp_path, FakeChain(empty=True))
    acquisition = scan(store, plan, RPC(chain))
    release = build(store, plan, [acquisition])
    import pyarrow.parquet as pq

    table = pq.read_table(store.root / "published" / release / "economic_legs.parquet")
    assert table.num_rows == 0 and "price" in table.column_names
    assert store.verify(release)["coverage"][0]["status"] == "confirmed_empty"


def test_hash_mismatch_revokes_current_preserves_evidence(tmp_path):
    store, plan, chain = prepared(tmp_path)
    acquisition = scan(store, plan, RPC(chain))
    release = build(store, plan, [acquisition])
    store.publish(release)
    chain.changed.add(100)
    with pytest.raises(PolygonError, match="withdrawn"):
        live_verify(store, RPC(chain), release)
    assert not (store.root / "published" / (plan + ".current.json")).exists()
    assert (store.root / "published" / release / "economic_legs.parquet").exists()
    with pytest.raises(PolygonError, match="invalidated"):
        build(store, plan, [acquisition])


def test_rpc_errors_sanitized_envelopes_and_limits():
    rpc = RPC(
        lambda body: {
            "jsonrpc": "2.0",
            "id": body["id"],
            "error": {"code": -1, "message": "https://rpc.invalid/SECRET"},
        }
    )
    with pytest.raises(PolygonError) as error:
        rpc.call("eth_chainId", [])
    assert "SECRET" not in str(error.value)
    with pytest.raises(PolygonError, match="allowlisted"):
        rpc.call("eth_sendTransaction", [])
    with pytest.raises(PolygonError, match="envelope"):
        RPC(lambda body: {"jsonrpc": "2.0", "id": False, "result": "0x89"}).call("eth_chainId", [])
    bounded = RPC(FakeChain(), max_calls=1)
    bounded.call("eth_chainId", [])
    with pytest.raises(PolygonError, match="bound"):
        bounded.call("eth_chainId", [])


def test_multiple_transaction_segments_are_normalized_independently():
    from polymarket_polygon_settlements.normalize import normalize_events

    other = replace(
        TARGET, market_id="2", condition_id="0x" + "e" * 64, token_index_sets={"21": 1, "22": 2}
    )
    events = [
        event("order_filled", "SELL", "11", 1_000_000, 600_000, 1),
        event("order_filled", "BUY", "11", 600_000, 1_000_000, 2),
        event("orders_matched", "BUY", "11", 600_000, 1_000_000, 3),
        event("order_filled", "SELL", "21", 2_000_000, 800_000, 4),
        event("order_filled", "BUY", "21", 800_000, 2_000_000, 5),
        event("orders_matched", "BUY", "21", 800_000, 2_000_000, 6),
    ]
    rows = normalize_events(events, [TARGET, other], {100: 6000})
    assert len(rows) == 2
    assert {row["market_id"] for row in rows} == {"1", "2"}
    assert len(normalize_events(events, [TARGET], {100: 6000})) == 1
    with pytest.raises(PolygonError, match="unmatched"):
        normalize_events(events[:-1], [TARGET, other], {100: 6000})


def test_saturation_cannot_be_silently_published(tmp_path):
    store, plan_id, chain = prepared(tmp_path)
    value = store.load_plan(plan_id)
    value.pop("contract")
    value["max_logs"] = 1
    plan_id = store.create_plan(value)
    with pytest.raises(PolygonError, match="Irreducibly"):
        scan(store, plan_id, RPC(chain))
    assert not list((store.root / "published").glob("*.current.json"))


def test_collateral_decimals_fail_closed_before_collection(tmp_path):
    class WrongDecimals(FakeChain):
        def __call__(self, body):
            response = super().__call__(body)
            if (
                body["method"] == "eth_call"
                and self.selectors[body["params"][0]["data"][2:10]] == "decimals()"
            ):
                response["result"] = "0x" + f"{18:064x}"
            return response

    _, _, markets, outcomes = metadata(tmp_path)
    with pytest.raises(PolygonError, match="decimals"):
        finalized_plan(
            RPC(WrongDecimals()), markets, outcomes, ["1"], [STANDARD_EXCHANGE], 100, 102
        )


def test_plan_at_finalized_head_accepts_interval_but_marks_last_minute_partial(tmp_path):
    _, _, markets, outcomes = metadata(tmp_path)
    plan = finalized_plan(RPC(FakeChain()), markets, outcomes, ["1"], [STANDARD_EXCHANGE], 100, 110)
    assert plan["to_block"] == 110
    assert plan["end_boundary_confirmed"] is False
    assert plan["end_timestamp_exclusive"] == 6601


def alternate_plan(store, original, **changes):
    data = dict(store.load_plan(original))
    data.pop("contract")
    data.update(changes)
    return store.create_plan(data)


def test_reopened_build_enforces_sealed_limits_before_decoding(tmp_path, monkeypatch):
    from polymarket_polygon_settlements.foundation import BudgetExceeded

    store, plan, chain = prepared(tmp_path)
    data = dict(store.load_plan(plan)["limits"])
    data["max_temp_bytes"] = 120_000
    small_plan = alternate_plan(store, plan, limits=data)
    acquisition = scan(store, small_plan, RPC(chain))
    reopened = Store(store.root, CONTRACT)
    monkeypatch.setattr(
        reopened, "read_relation", lambda *args: pytest.fail("decoded before resource preflight")
    )
    with pytest.raises(BudgetExceeded, match="working-set"):
        build(reopened, small_plan, [acquisition])
    assert reopened.limits.max_temp_bytes == 120_000
    assert not list((store.root / "published").glob("*.current.json"))


def test_money_outputs_include_venue_and_collateral_units(tmp_path):
    import pyarrow.parquet as pq

    store, plan, chain = prepared(tmp_path)
    acquisition = scan(store, plan, RPC(chain))
    release = build(store, plan, [acquisition])
    for name in ("economic_legs", "minute_aggregates"):
        rows = pq.read_table(store.root / "published" / release / (name + ".parquet")).to_pylist()
        assert rows[0]["venue"] == "polymarket"
        assert rows[0]["collateral_address"] == COLLATERAL
        assert rows[0]["ctf_collateral_address"] == COLLATERAL
        assert rows[0]["collateral_decimals"] == 6


def test_active_cross_plan_union_deduplicates_and_conflict_blocks_pointer(tmp_path):
    from polymarket_polygon_settlements.pipeline import LEG_SCHEMA, publish, published_legs

    store, plan, chain = prepared(tmp_path)
    acquisition = scan(store, plan, RPC(chain))
    release = build(store, plan, [acquisition])
    publish(store, release)
    other = alternate_plan(store, plan, to_block=103, end_timestamp_exclusive=6240)
    other_acquisition = scan(store, other, RPC(chain))
    other_release = build(store, other, [other_acquisition])
    publish(store, other_release)
    rows = published_legs(store, 16 * 1024**2)
    assert len(rows) == 1
    captures = store.committed_captures(acquisition_id=other_acquisition)
    bad_rows = [{**rows[0], "price": Decimal("0.7")}]
    conflicting = store.build_release(
        other,
        captures,
        {"economic_legs": bad_rows},
        [row for capture in captures for row in capture["coverage"]],
        schemas={"economic_legs": LEG_SCHEMA},
    )
    old_pointer = (store.root / "published" / (other + ".current.json")).read_bytes()
    with pytest.raises(PolygonError, match="across active plans"):
        publish(store, conflicting)
    assert (store.root / "published" / (other + ".current.json")).read_bytes() == old_pointer


def test_canonical_union_work_budget_checked_before_duckdb(tmp_path, monkeypatch):
    import polymarket_polygon_settlements.pipeline as pipeline
    from polymarket_polygon_settlements.foundation import BudgetExceeded
    from polymarket_polygon_settlements.pipeline import LEG_SCHEMA, published_legs

    store, plan, chain = prepared(tmp_path)
    acquisition = scan(store, plan, RPC(chain))
    captures = store.committed_captures(acquisition_id=acquisition)
    rows = normalize(
        [event("order_filled", "SELL", "11", 1_000_000, 600_000, 1)],
        event("order_filled", "BUY", "11", 600_000, 1_000_000, 2),
        event("orders_matched", "BUY", "11", 600_000, 1_000_000, 3),
    )
    release = store.build_release(
        plan,
        captures,
        {"economic_legs": rows * 100},
        [row for capture in captures for row in capture["coverage"]],
        schemas={"economic_legs": LEG_SCHEMA},
    )
    store.publish(release)
    monkeypatch.setattr(
        pipeline.duckdb,
        "connect",
        lambda *args, **kwargs: pytest.fail("opened DuckDB before preflight"),
    )
    with pytest.raises(BudgetExceeded, match="working-set"):
        published_legs(store, 2 * 1024**2)


def test_unrelated_corrupt_release_does_not_prevent_mismatch_withdrawal(tmp_path):
    store, plan, chain = prepared(tmp_path)
    acquisition = scan(store, plan, RPC(chain))
    release = build(store, plan, [acquisition])
    store.publish(release)
    bad = store.root / "published" / ("f" * 64)
    bad.mkdir()
    (bad / "manifest.json").write_bytes(b"invalid")
    chain.changed.add(100)
    with pytest.raises(PolygonError, match="withdrawn; unrelated corruption"):
        live_verify(store, RPC(chain), release)
    assert not (store.root / "published" / (plan + ".current.json")).exists()
    assert (store.root / ".state" / "header_mismatch_corruption.json").exists()
    assert (store.root / "published" / release / "economic_legs.parquet").exists()


def test_live_verify_holds_writer_lock_during_header_check(tmp_path):
    from filelock import Timeout

    store, plan, chain = prepared(tmp_path)
    acquisition = scan(store, plan, RPC(chain))
    release = build(store, plan, [acquisition])
    competing = Store(store.root, CONTRACT)
    checked = []

    def guarded(body):
        if body["method"] == "eth_getBlockByNumber":
            with pytest.raises(Timeout):
                with competing.lock:
                    pytest.fail("competing writer acquired root during live verification")
            checked.append(True)
        return chain(body)

    live_verify(store, RPC(guarded), release)
    assert checked
