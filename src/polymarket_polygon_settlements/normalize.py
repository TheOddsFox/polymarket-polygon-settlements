"""Economic legs adapted from the audited oddsfox-pipeline V2 normalizer."""

import hashlib
import json
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal
from typing import Sequence

from .codec import CHAIN_ID, Event, PolygonError

NORMALIZER_VERSION = "1"
MAX_VOLUME_RAW = 340_282_366_920_938_463_374


def decimal_units(raw: int, places: int = 6) -> Decimal:
    if not 0 <= raw <= MAX_VOLUME_RAW:
        raise PolygonError("Settlement volume exceeds exact safe bound")
    whole, fraction = divmod(raw, 10**places)
    return Decimal(f"{whole}.{fraction:0{places}d}")


def price(collateral: int, shares: int) -> Decimal:
    if not 0 < collateral <= shares:
        raise PolygonError("Price inputs require 0 < collateral <= shares")
    integer, remainder = divmod(collateral * 10**18, shares)
    if 2 * remainder > shares or (2 * remainder == shares and integer % 2):
        integer += 1
    return decimal_units(integer, 18)


@dataclass(frozen=True)
class Target:
    market_id: str
    condition_id: str
    exchange_address: str
    # Physical index sets come from chain proof, never source labels or ordinals.
    token_index_sets: dict[str, int]
    collateral_address: str
    ctf_collateral_address: str
    collateral_decimals: int = 6
    outcome_token_factory: str = ""
    exchange_code_sha256: str = ""

    @property
    def tokens(self) -> tuple[str, ...]:
        return tuple(self.token_index_sets)


def amounts(event: Event) -> tuple[int, int]:
    shares, collateral = (
        (event.taker_amount, event.maker_amount)
        if event.side == "BUY"
        else (event.maker_amount, event.taker_amount)
    )
    if not 0 < collateral <= shares:
        raise PolygonError("Invalid share/collateral amounts")
    decimal_units(shares)
    decimal_units(collateral)
    return shares, collateral


def normalize_segment(
    passive: Sequence[Event],
    active: Event,
    matched: Event,
    targets: Sequence[Target],
    block_timestamp: int,
) -> list[dict]:
    if not passive or active.kind != "order_filled" or matched.kind != "orders_matched":
        raise PolygonError("Malformed V2 segment boundary")
    segment = (*passive, active, matched)

    def location(event):
        return (
            event.exchange_address,
            event.block_number,
            event.block_hash,
            event.transaction_hash,
            event.transaction_index,
        )

    if any(location(event) != location(active) for event in segment):
        raise PolygonError("Segment crosses transaction boundaries")
    if [event.log_index for event in segment] != sorted({event.log_index for event in segment}):
        raise PolygonError("Segment log ordering is ambiguous")
    if (active.side, active.token_id, active.maker_amount, active.taker_amount) != (
        matched.side,
        matched.token_id,
        matched.maker_amount,
        matched.taker_amount,
    ):
        raise PolygonError("OrdersMatched does not exactly match active aggregate")
    by_token = {
        (target.exchange_address, token): target for target in targets for token in target.tokens
    }
    if not any(
        (event.exchange_address, event.token_id) in by_token for event in (*passive, active)
    ):
        return []
    target = by_token.get((active.exchange_address, active.token_id))
    if target is None:
        raise PolygonError("Unregistered active counterpart")
    if active.exchange_address != target.exchange_address:
        raise PolygonError("Target assigned to wrong exchange")
    digest = hashlib.sha256(
        json.dumps(
            [event.sanitized() for event in segment], sort_keys=True, separators=(",", ":")
        ).encode()
    ).hexdigest()
    expected_shares = expected_collateral = 0
    paired = False
    rows = []
    for event in passive:
        if by_token.get((event.exchange_address, event.token_id)) != target:
            raise PolygonError("Segment crosses conditions or unregistered passive token")
        shares, collateral = amounts(event)
        expected_shares += shares
        if event.token_id == active.token_id and event.side != active.side:
            kind, derived = "complementary", None
            expected_collateral += collateral
        elif event.token_id != active.token_id and event.side == active.side:
            kind, derived = ("mint" if active.side == "BUY" else "merge"), shares - collateral
            if derived <= 0:
                raise PolygonError("Derived collateral must be positive")
            paired = True
            expected_collateral += derived
        else:
            raise PolygonError("Unsupported V2 target match shape")
        legs = [(event.token_id, event.side, collateral, False, 0)]
        if derived is not None:
            legs.append((active.token_id, active.side, derived, True, 1))
        for token, side, cash, is_derived, ordinal in legs:
            rows.append(
                {
                    "venue": "polymarket",
                    "collateral_address": target.collateral_address,
                    "ctf_collateral_address": target.ctf_collateral_address,
                    "collateral_decimals": target.collateral_decimals,
                    "chain_id": CHAIN_ID,
                    "exchange_address": event.exchange_address,
                    "block_number": event.block_number,
                    "block_hash": event.block_hash,
                    "block_timestamp": block_timestamp,
                    "transaction_hash": event.transaction_hash,
                    "transaction_index": event.transaction_index,
                    "passive_log_index": event.log_index,
                    "active_log_index": active.log_index,
                    "matched_log_index": matched.log_index,
                    "leg_ordinal": ordinal,
                    "market_id": target.market_id,
                    "condition_id": target.condition_id,
                    "asset_kind": "ctf_token",
                    "asset_id": token,
                    "index_set": target.token_index_sets[token],
                    "order_side": side,
                    "source_token_id": event.token_id,
                    "source_maker_amount_raw": str(event.maker_amount),
                    "source_taker_amount_raw": str(event.taker_amount),
                    "share_amount_raw": str(shares),
                    "collateral_amount_raw": str(cash),
                    "share_volume": decimal_units(shares),
                    "gross_collateral_volume": decimal_units(cash),
                    "price": price(cash, shares),
                    "normalization_kind": kind,
                    "is_derived": is_derived,
                    "segment_sha256": digest,
                    "normalizer_version": NORMALIZER_VERSION,
                }
            )
    active_shares, active_collateral = amounts(active)
    if not paired:
        conserved = active_shares == expected_shares and active_collateral == expected_collateral
    elif active.side == "BUY":
        conserved = active_shares == expected_shares and active_collateral >= expected_collateral
    else:
        conserved = active_shares >= expected_shares and active_collateral == expected_collateral
    if not conserved:
        raise PolygonError("Active aggregate does not conserve economic amounts")
    return rows


def normalize_events(
    events: Sequence[Event], targets: Sequence[Target], timestamps: dict[int, int]
) -> list[dict]:
    locations = {
        (event.exchange_address, event.transaction_hash, event.log_index) for event in events
    }
    if len(locations) != len(events):
        raise PolygonError("Duplicate settlement log")
    by_transaction = defaultdict(list)
    for event in events:
        by_transaction[(event.exchange_address, event.transaction_hash)].append(event)
    rows = []
    for transaction in sorted(
        by_transaction.values(), key=lambda tx: (tx[0].block_number, tx[0].transaction_index)
    ):
        pending = []
        for event in sorted(transaction, key=lambda event: event.log_index):
            if event.kind == "order_filled":
                pending.append(event)
            else:
                if len(pending) < 2:
                    raise PolygonError("OrdersMatched lacks complete passive and active legs")
                rows.extend(
                    normalize_segment(
                        pending[:-1], pending[-1], event, targets, timestamps[event.block_number]
                    )
                )
                pending.clear()
        if pending:
            raise PolygonError("Transaction ended with unmatched OrderFilled")
    return rows


def leg_key(row: dict) -> tuple:
    return tuple(
        row[field]
        for field in (
            "chain_id",
            "exchange_address",
            "block_hash",
            "transaction_hash",
            "passive_log_index",
            "leg_ordinal",
        )
    )


def deduplicate_legs(rows: Sequence[dict]) -> list[dict]:
    by_key = {}
    for row in rows:
        key = leg_key(row)
        if key in by_key and by_key[key] != row:
            raise PolygonError("Conflicting economic leg identity")
        by_key[key] = row
    return sorted(
        by_key.values(),
        key=lambda row: (
            row["block_number"],
            row["transaction_index"],
            row["passive_log_index"],
            row["leg_ordinal"],
        ),
    )


def minute_aggregates(
    rows: Sequence[dict],
    targets: Sequence[Target],
    start_timestamp: int,
    end_timestamp_exclusive: int,
    max_buckets: int = 100_000,
    end_boundary_confirmed: bool = True,
) -> list[dict]:
    first, last = start_timestamp // 60 * 60, (end_timestamp_exclusive - 1) // 60 * 60
    if (
        end_timestamp_exclusive <= start_timestamp
        or ((last - first) // 60 + 1) * sum(len(target.tokens) for target in targets) > max_buckets
    ):
        raise PolygonError("Aggregate bucket bound exceeded or invalid coverage interval")
    buckets = defaultdict(list)
    for row in deduplicate_legs(rows):
        if not start_timestamp <= row["block_timestamp"] < end_timestamp_exclusive:
            raise PolygonError("Economic leg outside time coverage")
        buckets[
            (row["exchange_address"], row["asset_id"], row["block_timestamp"] // 60 * 60)
        ].append(row)
    result = []
    for target in targets:
        for token in target.tokens:
            for minute in range(first, last + 1, 60):
                legs = buckets[(target.exchange_address, token, minute)]
                full = (
                    start_timestamp <= minute
                    and minute + 60 <= end_timestamp_exclusive
                    and (end_boundary_confirmed or minute != last)
                )
                shares = sum(int(row["share_amount_raw"]) for row in legs)
                cash = sum(int(row["collateral_amount_raw"]) for row in legs)
                prices = [Decimal(row["price"]) for row in legs]
                result.append(
                    {
                        "venue": "polymarket",
                        "collateral_address": target.collateral_address,
                        "ctf_collateral_address": target.ctf_collateral_address,
                        "collateral_decimals": target.collateral_decimals,
                        "market_id": target.market_id,
                        "condition_id": target.condition_id,
                        "exchange_address": target.exchange_address,
                        "asset_kind": "ctf_token",
                        "asset_id": token,
                        "minute_timestamp": minute,
                        "minute_utc": datetime.fromtimestamp(minute, timezone.utc).isoformat(),
                        "coverage": "complete" if full else "partial_boundary",
                        "observed_leg_count": len(legs),
                        "leg_count": len(legs) if full else None,
                        "share_volume": decimal_units(shares) if legs or full else None,
                        "gross_collateral_volume": decimal_units(cash) if legs or full else None,
                        "vwap": price(cash, shares) if shares else None,
                        "open": prices[0] if prices else None,
                        "high": max(prices) if prices else None,
                        "low": min(prices) if prices else None,
                        "close": prices[-1] if prices else None,
                    }
                )
    return result
