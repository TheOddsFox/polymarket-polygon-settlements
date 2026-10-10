# polymarket-polygon-settlements

Finite, local collection of **finalized Polygon CTF Exchange V2 economic fills**. Explicit market selections come from `polymarket-events`; this repository owns its own fresh data and never imports or edits `oddsfox-pipeline`.

Supported: chain 137, standard exchange `0xe111180000d2663c0091e4f400237545b87b996b`, neg-risk exchange `0xe2222d279d744050d28e00520010520000310f59`, complete chain-verified binary CTF conditions and six-decimal collateral. Protocol V2 positions, exchange V3, oracle resolution, redemption, trading and wallets are outside v1.

## Install and verify

```sh
uv sync --locked
scripts/verify-fast
scripts/verify
uv run --locked polymarket-polygon-settlements --help
```

Python 3.12 is required. The installed CLI runs outside this checkout. `--root` precedes the command, defaults to `./data`, and must be Git-ignored if inside any checkout. A single writer lock covers a whole scan/build. There are no background services, schedulers or automatic deletions.

## Plan → scan → build → publish

First use the events repository's targeted metadata export. Keep the output `manifest_sha256` as the trusted digest supplied to this consumer. Plans pin and validate a local immutable copy; later producer cleanup cannot break replay.

Set `POLYGON_RPC_URL` to an explicit standard-port HTTPS endpoint with historical `eth_call`, finalized block tags and EIP-1898 block-hash queries enabled. Supply credentials through the environment; the CLI does not load `.env`, store the endpoint or echo provider error messages. HTTPS redirects, ambient proxies and non-public destinations are refused.

```sh
uv run --locked polymarket-polygon-settlements --root ./data plan \
  --metadata /absolute/path/to/events-bundle \
  --metadata-digest MANIFEST_SHA256 \
  --market 12345 --exchange standard \
  --from-block 90000000 --to-block 90000010 \
  --max-requests 500 --max-blocks 100 \
  --max-download-bytes 67108864 --max-storage-bytes 1073741824 \
  --max-response-bytes 16777216 --max-temp-bytes 67108864

uv run --locked polymarket-polygon-settlements --root ./data scan --plan PLAN_ID
uv run --locked polymarket-polygon-settlements --root ./data build \
  --plan PLAN_ID --acquisition ACQUISITION_ID
uv run --locked polymarket-polygon-settlements --root ./data publish --release RELEASE_ID
uv run --locked polymarket-polygon-settlements --root ./data verify --release RELEASE_ID
uv run --locked polymarket-polygon-settlements --root ./data status
```

Repeat `--market` for multiple conditions on the **same** selected exchange. Use separate plans for different exchanges. All blocks in the inclusive interval must be finalized; a request past the finalized head fails instead of clipping. The next finalized block, when available, establishes the end time boundary. A plan ending exactly at the finalized head is accepted but the final minute remains partial.

Planning verifies the actual exchange asset configuration at the first and last blocks. Source outcome labels and the metadata's one-based ordinal never determine token complements. The pinned V2 contract has no token registry: its audited `_validateTokenIds` computes the two position IDs for index sets 1 and 2 using `getCtfCollateral`. This collector reproduces that rule through CTF view calls, verifies outcome-slot count and collateral units, and records the physical index sets separately.

Default plan bounds: 1,000 HTTP attempts, 20,000 blocks, 10,000 discovery logs per leaf, 100,000 minute buckets, 256 MiB downloaded, 16 MiB per response, 256 MiB temporary output, 1 GiB retained root. Every bound is stored in the plan; retries and partial responses consume transport limits. Offline builds restore the sealed limits on a reopened root and conservatively preflight Parquet uncompressed sizes, row counts and derived minute counts before decoding. Canonical cross-plan reads also preflight and use bounded temporary DuckDB queries. Raising limits is an operator choice, not an automatic fallback.

## Published contract

`oddsfox.polymarket.polygon-settlements.v1` is a checksum-verified immutable directory containing:

- `sanitized_events.parquet`: decoded V2 event fields and chain locators. Amounts remain exact integer strings.
- `economic_legs.parquet`: venue, trading collateral, CTF collateral and decimals, raw integer and fixed-decimal amounts, 18-place half-even prices, complementary/mint/merge provenance and normalizer revision.
- `minute_aggregates.parquet`: the same venue/collateral units, per-exchange/native-asset OHLC, counts, gross quantities and VWAP computed from total collateral ÷ total shares.
- `coverage.json`, the sealed plan, input capture IDs and a versioned manifest.

The natural economic key is `(chain_id, exchange_address, block_hash, transaction_hash, passive_log_index, leg_ordinal)`. Active aggregate events are evidence, not extra economic legs. Mixed makers and legitimate maker-asset refunds preserve the audited normalization rules. Builds may combine repeated acquisitions of the **same** plan. Publication additionally validates all active plan releases together: identical natural legs deduplicate and conflicting identities block pointer promotion. Read the canonical cross-plan economic union with `published-legs --max-temp-bytes 268435456`. A candidate replaces its own plan’s previous pointer during validation. Never sum overlapping per-plan minute tables; aggregate the canonical economic legs instead.

A full empty minute has count/volume zero and null prices. Partial start/end minutes have explicit `partial_boundary` coverage; unobserved intervals cannot be turned into empty trading activity. Failed or unfinished block ranges cannot build a release. Successful empty full scans can publish typed empty tables.

## Recovery and operational acceptance

See [the runbook](docs/RUNBOOK.md). Captures commit only after payloads and checksums; the manifest is the checkpoint. A new scan makes a new acquisition; `--resume` explicitly continues one prior acquisition. The scan emits its acquisition ID on stderr before collecting leaves, so a failed invocation can be resumed. Immutable completed leaves skip only after hash verification and live header revalidation.

`verify` checks local integrity. `verify --live --max-requests 500` additionally rechecks pinned finalized hashes; it does not reacquire price data or claim independent-provider correctness. A confirmed hash mismatch invalidates affected acquisitions/plans/releases, removes an affected current pointer and retains all bytes for diagnosis. No release is automatically republished.

The test suite uses synthetic offline source fixtures and adapted economic regressions. No live production interval is claimed verified by installation or CI. Before operational use, run a small finalized interval with the intended endpoint, compare a known receipt, record attempts/downloaded bytes, repeat offline build, and test resume and live verification with an operator-approved source.

## Source and attribution

Decoder and normalizer mechanisms and economic regression cases are adapted from the MIT-licensed `hypertrial/oddsfox-pipeline`; no runtime dependency or state migration is introduced. See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

Pinned ABI/semantic reference: [Polymarket CTF Exchange V2](https://github.com/Polymarket/ctf-exchange-v2/tree/ccc0596074f4dfd62c944fbca4de252893b82b4b). Solidity source is not vendored. Current deployment boundaries: [official contracts documentation](https://docs.polymarket.com/resources/contracts).

## Repeatable live smoke test

Run from this repository after `uv sync --locked`. This is opt-in; ordinary tests and CI stay offline.

```sh
POLYGON_RPC_URL=https://polygon-bor-rpc.publicnode.com uv run --locked python -m polymarket_polygon_settlements.smoke --events-report /absolute/path/to/events/report.json --blocks 20
```

Every invocation creates a fresh ignored `data/smoke/<uuid>` root and prints the absolute `report.json` path. Use `--output <fresh-path>` to name a run. Never reuse an output directory. Reports retain the steps, measured requests/bytes, configured limits and coverage. Failed/timed-out commands make `accounting_complete` false; their totals are known lower bounds. No paid requests are made. Run the events smoke first and pass its report to the consumers; consumers validate and pin its metadata bundle. Select an explicit currently active, unambiguous market when the example market closes.

A pass requires chain proof, an entirely finalized finite interval, nonempty economic legs, resume, offline replay, publication and live hash verification. Empty intervals fail explicitly because they do not test fill decoding; choose a more active usable CTF market or use `--blocks 100`. The standard exchange is tested. Protocol V2 positions are rejected. Discovery allows 5 attempts/1 MiB; plan/scan allow 100 attempts/8 MiB each, and live verification allows 20 attempts/256 MiB. Retained acquisition storage is capped at 64 MiB.

Free public RPC availability varies. On 2026-10-10 publicnode accepted a 20-block scan but rejected a 100-block request as requiring archive access; other free endpoints rejected historical proof calls. These are failures, not zero-volume evidence. `POLYGON_RPC_URL` may select another public HTTPS endpoint; the report never includes it. Without nonempty legs this repository's live economic normalization remains unverified.
