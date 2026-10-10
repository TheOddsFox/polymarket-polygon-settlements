# Project agent notes

Public OddsFox repository. Finalized Polygon CTF Exchange V2 economic legs for verified binary conditions. Protocol V2 positions, resolution and redemption are outside v1.

Python 3.12, uv, immutable captures and Parquet; no dlt, dbt or Dagster. Read README.md for operator commands. Use the oddsfox-polymarket-polygon-settlements-engineering Pad workspace and canonical verify wrappers.

## Invariants

- Keep oddsfox-pipeline untouched; no runtime imports or state migration.
- Data, state, credentials, captures and Pad bodies stay out of Git and distributions.
- Exact decimals and typed native identities; never infer complements from labels.
- Capture manifests are checkpoints; unresolved failures cannot promote publication.
- Paid calls are disabled by default and durably reserved per actual attempt.
- Tests are offline; production source checks are bounded operator actions.
- Do not commit, push or publish unless explicitly requested.

## Verification

Fast: diff check, locked Ruff lint/format and pytest. Completion additionally checks lock, locked sync and builds distributions. Use scripts/verify-fast and scripts/verify.
