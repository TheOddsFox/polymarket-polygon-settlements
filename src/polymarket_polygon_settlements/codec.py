"""Sanitized CTF Exchange V2 event decoding, adapted from oddsfox-pipeline."""

import re
from dataclasses import asdict, dataclass
from typing import Any

ABI_REVISION = "ccc0596074f4dfd62c944fbca4de252893b82b4b"
CHAIN_ID = 137
STANDARD_EXCHANGE = "0xe111180000d2663c0091e4f400237545b87b996b"
NEG_RISK_EXCHANGE = "0xe2222d279d744050d28e00520010520000310f59"
EXCHANGES = (STANDARD_EXCHANGE, NEG_RISK_EXCHANGE)
CTF = "0x4d97dcd97ec945f40cf65f87097ace5ea0476045"
ORDER_FILLED_TOPIC = "0xd543adfd945773f1a62f74f0ee55a5e3b9b1a28262980ba90b1a89f2ea84d8ee"
ORDERS_MATCHED_TOPIC = "0x174b3811690657c217184f89418266767c87e4805d09680c39fc9c031c0cab7c"
EVENT_TOPICS = (ORDER_FILLED_TOPIC, ORDERS_MATCHED_TOPIC)


class PolygonError(ValueError):
    """Sanitized protocol or economic validation failure."""


class RangeLimit(PolygonError):
    """Provider explicitly reported an oversized range."""


def hex32(value: Any) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"0x[0-9a-fA-F]{64}", value):
        raise PolygonError("Expected a 32-byte hash")
    return value.lower()


def address(value: Any) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"0x[0-9a-fA-F]{40}", value):
        raise PolygonError("Expected an address")
    return value.lower()


def quantity(value: Any) -> int:
    if not isinstance(value, str) or not re.fullmatch(r"0x(?:0|[1-9a-fA-F][0-9a-fA-F]*)", value):
        raise PolygonError("Expected a canonical hex quantity")
    return int(value, 16)


@dataclass(frozen=True)
class Event:
    kind: str
    exchange_address: str
    block_number: int
    block_hash: str
    transaction_hash: str
    transaction_index: int
    log_index: int
    side: str
    token_id: str
    maker_amount: int
    taker_amount: int

    def sanitized(self) -> dict:
        row = asdict(self)
        row["maker_amount"] = str(self.maker_amount)
        row["taker_amount"] = str(self.taker_amount)
        return row

    @classmethod
    def from_sanitized(cls, value: dict) -> "Event":
        if set(value) != set(cls.__dataclass_fields__):
            raise PolygonError("Unexpected sanitized event inventory")
        event = cls(
            **{
                **value,
                "maker_amount": int(value["maker_amount"]),
                "taker_amount": int(value["taker_amount"]),
            }
        )
        if event.kind not in {"order_filled", "orders_matched"} or event.side not in {
            "BUY",
            "SELL",
        }:
            raise PolygonError("Invalid sanitized event kind or side")
        address(event.exchange_address)
        for field in (event.block_hash, event.transaction_hash):
            hex32(field)
        if not event.token_id.isdecimal() or int(event.token_id) <= 0:
            raise PolygonError("Invalid sanitized token")
        for value in (event.block_number, event.transaction_index, event.log_index):
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise PolygonError("Invalid sanitized location")
        if min(event.maker_amount, event.taker_amount) <= 0:
            raise PolygonError("Invalid sanitized amounts")
        return event


def decode_log(raw: dict) -> Event:
    if raw.get("removed") is not False:
        raise PolygonError("Removed or incomplete log")
    topics = raw.get("topics")
    if not isinstance(topics, list) or not topics:
        raise PolygonError("Missing event topics")
    topics = [hex32(value) for value in topics]
    if topics[0] == ORDER_FILLED_TOPIC and len(topics) == 4:
        kind, words = "order_filled", 7
    elif topics[0] == ORDERS_MATCHED_TOPIC and len(topics) == 3:
        kind, words = "orders_matched", 4
    else:
        raise PolygonError("Unexpected V2 event layout")
    data = raw.get("data")
    if not isinstance(data, str) or not re.fullmatch(rf"0x[0-9a-fA-F]{{{words * 64}}}", data):
        raise PolygonError("Unexpected V2 data word count")
    side, token, maker, taker = [int(data[2 + i * 64 : 2 + (i + 1) * 64], 16) for i in range(4)]
    if side not in (0, 1) or min(token, maker, taker) <= 0:
        raise PolygonError("Invalid V2 side/token/amounts")
    return Event(
        kind,
        address(raw.get("address")),
        quantity(raw.get("blockNumber")),
        hex32(raw.get("blockHash")),
        hex32(raw.get("transactionHash")),
        quantity(raw.get("transactionIndex")),
        quantity(raw.get("logIndex")),
        "BUY" if side == 0 else "SELL",
        str(token),
        maker,
        taker,
    )
