# Local operator runbook

## Failed scan

1. Preserve the root and inspect `status` for acquisition IDs. The scan prints its acquisition ID before collection.
2. Fix the endpoint capability or adjust resource bounds by making a **new plan**. Do not edit a sealed plan or checkpoint.
3. For an unchanged plan, run `scan --plan PLAN_ID --resume ACQUISITION_ID`. Headers are live-verified before any skip. Only committed leaves resume; unfinished ranges are collected again.
4. Build using an explicit acquisition inventory, verify, then publish. A failed build or scan never changes an existing current pointer.

A saturated range splits only on explicit provider size errors or the configured log bound. A saturated single block fails; use an endpoint supporting complete responses. A provider silently returning truncated successful results cannot be independently disproved by this collector. Its completeness guarantee is relative to the read-only endpoint, receipt cross-checks and explicit saturation gates.

## Header mismatch

Do not override the mismatch or restore a current pointer by hand. Affected bytes remain available, but invalidated plans/acquisitions cannot build. Create a new plan against canonical finalized chain state, scan fresh evidence and publish a new independently verified release. Old immutable evidence remains for audit. The known affected pointer is removed before inspecting unrelated releases. If another release is corrupt, `.state/header_mismatch_corruption.json` records that recovery gap; repair or quarantine corrupt evidence before relying on a full-root verification. Live verification holds the writer lock throughout hash checks and invalidation.

## Offline replay and backup

Copy the entire root while no writer is running, including `inputs`, `plans`, `acquisitions`, `published` and `.state`. Keep permissions restrictive and the copy outside Git. On the restored root, run `verify`; `build` over the same sealed input inventory should reproduce the same semantic records/release identity under the recorded code revision.

Root-level `verify` and `status` check active plan pointers as well as immutable evidence. Malformed pointers, incorrect manifest digests, pointers assigned to another plan, missing releases and pointers to invalidated work fail verification. `verify --release` checks a named immutable release independently; it does not validate the active pointer.

Offline replay re-normalizes **sanitized decoded evidence**. Full RPC bodies, raw topics, wallet addresses and order hashes are intentionally transient; ABI re-decoding requires a new online acquisition. Preserve the original package/lock revision with the backup.

Do not manually delete data referenced by a manifest. There is no automatic pruning or root reset command. Storage limits stop new work; choose a larger bounded allocation or a fresh operator root deliberately.

## Credentials and public artifacts

RPC paths/query strings may contain credentials. Never put them in tickets, screenshots, Git, manifests or command examples. Only use the environment variable. The code sanitizes transport errors and retains no endpoint. Transaction hashes and block hashes are public chain locators and remain linkable; sanitized evidence is not anonymous.

Before publishing package artifacts, run `scripts/verify` and inspect Git and wheel/sdist contents. No actual captures, Parquet outputs, DuckDB databases, data roots, `.env` files, Pad bodies or private reference inputs belong in a public distribution.

## Bounded source acceptance

CI is offline. An operator should record the code/lock revision, metadata digest, chain ID, interval, finalized head, endpoint label (no credentials), attempt count, downloaded bytes, coverage and release ID for a small source check. Verify one known complete receipt and mint/merge or complementary segment, repeat the offline build, rerun `scan --resume`, then `verify --live`. Paid PMXT feeds are outside this repository.

## Overlapping plans

Use `published-legs --max-temp-bytes BYTES` for the bounded canonical union of verified active plan pointers. Identical economic keys appear once; contradictory legs prevent promotion. Plan-specific minute tables describe their own intervals and must not be summed across overlapping plans. Retaining old releases does not include them in this union unless their plan pointer is active.
