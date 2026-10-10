"""Read-only RPC protocol and finalized target proof for the pinned exchange ABI."""

import hashlib
import re
from dataclasses import asdict, dataclass
from typing import Any, Callable

from .codec import (
    CTF,
    EVENT_TOPICS,
    EXCHANGES,
    ORDERS_MATCHED_TOPIC,
    PolygonError,
    RangeLimit,
    address,
    decode_log,
    hex32,
    quantity,
)
from .normalize import Target, normalize_events

READ_METHODS = {
    "eth_chainId",
    "eth_getBlockByNumber",
    "eth_getTransactionReceipt",
    "eth_getLogs",
    "eth_getCode",
    "eth_call",
    "web3_sha3",
}


@dataclass(frozen=True)
class Block:
    number: int
    hash: str
    timestamp: int


class RPC:
    def __init__(self, post: Callable[[dict], Any], *, max_calls: int = 1000):
        if max_calls <= 0:
            raise ValueError("RPC call bound must be positive")
        self.post, self.max_calls, self.calls = post, max_calls, 0
        self.selectors = {}

    def call(self, method: str, params: list) -> Any:
        if method not in READ_METHODS:
            raise PolygonError("RPC method is not read-only allowlisted")
        if self.calls >= self.max_calls:
            raise PolygonError("RPC call bound exhausted")
        self.calls += 1
        result = self.post({"jsonrpc": "2.0", "id": self.calls, "method": method, "params": params})
        if (
            not isinstance(result, dict)
            or result.get("jsonrpc") != "2.0"
            or type(result.get("id")) is not int
            or result["id"] != self.calls
            or ("result" in result) == ("error" in result)
        ):
            raise PolygonError("Malformed RPC envelope")
        if "error" in result:
            error = result["error"]
            if not isinstance(error, dict) or type(error.get("code")) is not int:
                raise PolygonError("Malformed RPC error")
            # Provider text is inspected transiently and is never persisted/logged.
            message = str(error.get("message", "")).lower()
            if error["code"] in {-32005, -32016, -32602, -32000} and any(
                text in message
                for text in (
                    "block range",
                    "too many results",
                    "query returned",
                    "response size",
                    "limit exceeded",
                )
            ):
                raise RangeLimit("Provider range limit")
            raise PolygonError(f"RPC error code {error['code']}")
        return result["result"]

    def block(self, number: int | str) -> Block:
        value = self.call(
            "eth_getBlockByNumber", [hex(number) if isinstance(number, int) else number, False]
        )
        if not isinstance(value, dict):
            raise PolygonError("Finalized block is unavailable")
        block = Block(
            quantity(value.get("number")),
            hex32(value.get("hash")),
            quantity(value.get("timestamp")),
        )
        if isinstance(number, int) and block.number != number:
            raise PolygonError("RPC returned wrong block")
        return block

    def word_call(self, contract: str, signature: str, args: str, block: Block) -> int:
        if signature not in self.selectors:
            digest = hex32(self.call("web3_sha3", ["0x" + signature.encode().hex()]))
            self.selectors[signature] = digest[2:10]
        result = self.call(
            "eth_call",
            [
                {"to": contract, "data": "0x" + self.selectors[signature] + args},
                {"blockHash": block.hash, "requireCanonical": True},
            ],
        )
        if not isinstance(result, str) or not re.fullmatch(r"0x[0-9a-fA-F]{64}", result):
            raise PolygonError("View call must return one ABI word")
        return int(result, 16)

    def address_call(self, contract: str, signature: str, block: Block) -> str:
        result = self.word_call(contract, signature, "", block)
        if not 0 < result < 2**160:
            raise PolygonError("View did not return nonzero address")
        return f"0x{result:040x}"

    def logs(self, exchange: str, start: int, end: int) -> list[dict]:
        result = self.call(
            "eth_getLogs",
            [
                {
                    "address": exchange,
                    "fromBlock": hex(start),
                    "toBlock": hex(end),
                    "topics": [ORDERS_MATCHED_TOPIC],
                }
            ],
        )
        if not isinstance(result, list) or any(not isinstance(row, dict) for row in result):
            raise PolygonError("Malformed discovery log response")
        return result

    def receipt(self, tx: str) -> list[dict]:
        value = self.call("eth_getTransactionReceipt", [tx])
        if (
            not isinstance(value, dict)
            or hex32(value.get("transactionHash")) != tx
            or quantity(value.get("status")) != 1
        ):
            raise PolygonError("Successful complete transaction receipt unavailable")
        location = (
            quantity(value.get("blockNumber")),
            hex32(value.get("blockHash")),
            quantity(value.get("transactionIndex")),
        )
        logs = value.get("logs")
        if not isinstance(logs, list) or any(not isinstance(row, dict) for row in logs):
            raise PolygonError("Receipt logs unavailable")
        indices = []
        for raw in logs:
            if (
                raw.get("removed") is not False
                or hex32(raw.get("transactionHash")) != tx
                or (
                    quantity(raw.get("blockNumber")),
                    hex32(raw.get("blockHash")),
                    quantity(raw.get("transactionIndex")),
                )
                != location
            ):
                raise PolygonError("Receipt has inconsistent log locators")
            indices.append(quantity(raw.get("logIndex")))
        if indices != sorted(set(indices)):
            raise PolygonError("Receipt contains unordered or duplicate logs")
        return logs


def proof_target(
    rpc: RPC, market: dict, outcomes: list[dict], exchange: str, block: Block
) -> Target:
    exchange = address(exchange)
    if exchange not in EXCHANGES:
        raise PolygonError("Unsupported audited exchange")
    if len(outcomes) != 2 or any(row.get("asset_kind") != "ctf_token" for row in outcomes):
        raise PolygonError("Only complete binary CTF conditions supported")
    condition = hex32(market.get("condition_id"))
    if any(row.get("condition_id") != condition for row in outcomes):
        raise PolygonError("Metadata condition mapping is ambiguous")
    tokens = {row["asset_id"] for row in outcomes}
    if len(tokens) != 2 or any(not token.isdecimal() or int(token) <= 0 for token in tokens):
        raise PolygonError("Condition lacks two distinct native tokens")
    code = rpc.call("eth_getCode", [exchange, {"blockHash": block.hash, "requireCanonical": True}])
    if (
        not isinstance(code, str)
        or not re.fullmatch(r"0x(?:[0-9a-fA-F]{2})+", code)
        or code == "0x00"
    ):
        raise PolygonError("Exchange is not deployed at proof block")
    ctf = rpc.address_call(exchange, "getCtf()", block)
    if ctf != CTF:
        raise PolygonError("Unsupported CTF implementation")
    collateral = rpc.address_call(exchange, "getCollateral()", block)
    ctf_collateral = rpc.address_call(exchange, "getCtfCollateral()", block)
    factory = rpc.address_call(exchange, "getOutcomeTokenFactory()", block)
    if rpc.word_call(collateral, "decimals()", "", block) != 6:
        raise PolygonError("Unsupported collateral decimals")
    if rpc.word_call(ctf_collateral, "decimals()", "", block) != 6:
        raise PolygonError("Unsupported CTF collateral decimals")
    if rpc.word_call(ctf, "getOutcomeSlotCount(bytes32)", condition[2:], block) != 2:
        raise PolygonError("Condition is not chain-verified binary")
    token_index_sets = {}
    for index_set in (1, 2):
        collection = rpc.word_call(
            ctf,
            "getCollectionId(bytes32,bytes32,uint256)",
            "0" * 64 + condition[2:] + f"{index_set:064x}",
            block,
        )
        token = rpc.word_call(
            ctf,
            "getPositionId(address,bytes32)",
            ctf_collateral[2:].rjust(64, "0") + f"{collection:064x}",
            block,
        )
        token_index_sets[str(token)] = index_set
    if set(token_index_sets) != tokens:
        raise PolygonError("Tokens do not match exchange condition validation rule")
    # Pinned V2 validates these computed IDs directly; it has no registry view.
    if factory == "0x" + "0" * 40:
        raise PolygonError("Invalid outcome token factory")
    return Target(
        str(market["market_id"]),
        condition,
        exchange,
        token_index_sets,
        collateral,
        ctf_collateral,
        6,
        factory,
        hashlib.sha256(bytes.fromhex(code[2:])).hexdigest(),
    )


def finalized_plan(
    rpc: RPC,
    market_rows: list[dict],
    outcomes: list[dict],
    selected: list[str],
    exchanges: list[str],
    start: int,
    end: int,
) -> dict:
    if (
        not selected
        or len(set(selected)) != len(selected)
        or not exchanges
        or len(set(exchanges)) != len(exchanges)
        or start < 0
        or end < start
    ):
        raise PolygonError("Explicit unique targets and inclusive block interval required")
    selected_outcomes = [row for row in outcomes if row["market_id"] in selected]
    if any(row.get("asset_kind") != "ctf_token" for row in selected_outcomes):
        raise PolygonError("Protocol V2 positions unsupported; rejected before RPC")
    markets = {str(row["market_id"]): row for row in market_rows}
    if set(selected) - set(markets):
        raise PolygonError("Requested metadata market absent")
    if any(
        len([row for row in selected_outcomes if row["market_id"] == market_id]) != 2
        for market_id in selected
    ):
        raise PolygonError("Metadata must nominate complete binary pairs before RPC")
    if any(address(exchange) not in EXCHANGES for exchange in exchanges):
        raise PolygonError("Unsupported audited exchange")
    if quantity(rpc.call("eth_chainId", [])) != 137:
        raise PolygonError("RPC chain must be Polygon 137")
    head = rpc.block("finalized")
    if end > head.number:
        raise PolygonError("Whole requested interval must be finalized")
    first, last = rpc.block(start), rpc.block(end)
    following = rpc.block(end + 1) if end < head.number else None
    if first.timestamp > last.timestamp or (following and following.timestamp <= last.timestamp):
        raise PolygonError("Nonmonotonic block timestamp boundaries")
    targets = []
    for exchange in exchanges:
        for market_id in selected:
            rows = [row for row in selected_outcomes if row["market_id"] == market_id]
            left = proof_target(rpc, markets[market_id], rows, exchange, first)
            right = proof_target(rpc, markets[market_id], rows, exchange, last)
            if left != right:
                raise PolygonError("Exchange asset configuration changed across interval")
            targets.append(asdict(left))
    return {
        "chain_id": 137,
        "from_block": start,
        "to_block": end,
        "targets": targets,
        "headers": [
            asdict(block)
            for block in {
                block.number: block
                for block in [head, first, last, *([following] if following else [])]
            }.values()
        ],
        "finalized_head": asdict(head),
        "start_timestamp": first.timestamp,
        "end_timestamp_exclusive": following.timestamp if following else last.timestamp + 1,
        "end_boundary_confirmed": following is not None,
    }


def collect_leaf(
    rpc: RPC, exchange: str, start: int, end: int, targets: list[Target], *, max_logs: int
) -> tuple[list[dict], list[dict], list[dict]]:
    raw_discoveries = rpc.logs(exchange, start, end)
    if len(raw_discoveries) >= max_logs:
        raise RangeLimit("Discovery reached configured saturation bound")
    discoveries = [decode_log(raw) for raw in raw_discoveries]
    if any(
        event.kind != "orders_matched"
        or event.exchange_address != exchange
        or not start <= event.block_number <= end
        for event in discoveries
    ):
        raise PolygonError("Discovery outside request scope")
    if len({(event.transaction_hash, event.log_index) for event in discoveries}) != len(
        discoveries
    ):
        raise PolygonError("Duplicate discovery identity")
    target_tokens = {token for target in targets for token in target.tokens}
    discovered = [event for event in discoveries if event.token_id in target_tokens]
    events = []
    for tx in dict.fromkeys(event.transaction_hash for event in discovered):
        receipt = rpc.receipt(tx)
        # Decode the complete exchange segment, including other conditions in tx.
        events.extend(
            decode_log(raw)
            for raw in receipt
            if str(raw.get("address", "")).lower() == exchange
            and isinstance(raw.get("topics"), list)
            and raw["topics"]
            and str(raw["topics"][0]).lower() in EVENT_TOPICS
        )
    if any(not start <= event.block_number <= end for event in events):
        raise PolygonError("Receipt event outside requested blocks")
    expected = sorted(
        (event.sanitized() for event in discovered),
        key=lambda row: (row["block_number"], row["transaction_index"], row["log_index"]),
    )
    actual = sorted(
        (
            event.sanitized()
            for event in events
            if event.kind == "orders_matched" and event.token_id in target_tokens
        ),
        key=lambda row: (row["block_number"], row["transaction_index"], row["log_index"]),
    )
    if actual != expected:
        raise PolygonError("Discovery and full receipts disagree")
    headers = {
        number: rpc.block(number)
        for number in {start, end, *(event.block_number for event in events)}
    }
    if any(headers[event.block_number].hash != event.block_hash for event in events):
        raise PolygonError("Receipt event disagrees with finalized header")
    legs = normalize_events(
        events, targets, {number: header.timestamp for number, header in headers.items()}
    )
    return (
        [event.sanitized() for event in events if event.token_id in target_tokens],
        legs,
        [asdict(header) for header in headers.values()],
    )


def adaptive_leaves(
    rpc: RPC, exchange: str, start: int, end: int, targets: list[Target], *, max_logs: int
):
    try:
        events, legs, headers = collect_leaf(rpc, exchange, start, end, targets, max_logs=max_logs)
        yield start, end, events, legs, headers
    except RangeLimit:
        if start == end:
            raise PolygonError("Irreducibly saturated single-block discovery") from None
        middle = (start + end) // 2
        yield from adaptive_leaves(rpc, exchange, start, middle, targets, max_logs=max_logs)
        yield from adaptive_leaves(rpc, exchange, middle + 1, end, targets, max_logs=max_logs)
