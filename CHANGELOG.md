# Changelog
All notable changes to this project will be documented in this file.
This project adheres to [Keep a Changelog](https://keepachangelog.com/) and uses [Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-08-13
First public release. A dependency-free toolkit for auditing automated decisions: policy checks, a tamper-evident log, drift and fairness monitoring, and portfolio thresholds that fail a pipeline on a breach.

### Added
- Declarative JSON constraints (`ratio_max`, `ratio_min`, `lte_field`, `value_max`, `value_min`, `positive`, `in_set`) with the combinators `all_of`, `any_of` and `not`, which nest. `register_constraint_type` adds domain types without editing the package and without `eval`.
- A tamper-evident log: linear hash chain in append-only JSON Lines, one signed block per line, appended with fsync, so adding a block is O(1). Ed25519 by default — pure-Python RFC 8032, validated against the section 7.1 vectors — so verification needs only the public key. HMAC-SHA256 is available via `--scheme hmac` for speed, at the cost of non-repudiation.
- Merkle tree over the same blocks (RFC 6962). Inclusion proofs show one record is in the log described by a signed tree head, without disclosing any other record; consistency proofs show a later log still carries an earlier one as an unchanged prefix. Both are self-contained JSON: `prove` and `verify-proof`.
- Signed checkpoints recording the head block and the Merkle root, so `checkpoint --check` covers the whole history behind that block.
- Windowed mean-shift drift detection, with the windows persisted in `drift_state.json` and read and written under the log's own lock, so drift works under one-decision-per-invocation integration and across several writers.
- Per-segment fairness metrics with 95% Wilson intervals, and portfolio thresholds (`check`) over approval-rate span, four-fifths ratio, override-rate gap, drift-alert rate and degraded share, extensible via `register_aggregate_rule`.
- Portfolio summary as JSON, carrying the integrity verdict for the log it describes, and a self-contained HTML report.
- `verify --stream`, `summary --stream` and `check --stream`, which read the log one record at a time. On a 20 000-record chain peak memory drops from 113 MiB to 0.1 MiB; the tests assert the streamed and loaded passes agree on the verdict, the counts, the Merkle root and the error messages word for word.
- Optional native Ed25519 backends (`cryptography`, `PyNaCl`), auto-detected, producing identical bytes to the bundled implementation. Neither is a dependency.
- `ARCHITECTURE.md`: the invariants a change can break in silence, and the reasoning behind the decisions taken deliberately.

### Guarantees
The toolkit states what it could not establish. The guarantees that carry weight:
- A field a rule needs but the context does not carry is a violation of severity `error`, never read as zero. In a combination, a branch that could not be evaluated does not fail the rule and does not override a branch that settled it, so the verdict does not depend on the order the rules were written in.
- A malformed rule, and a threshold that is missing or is not a number, are refused when the policy file is read. A rule the data cannot support is reported as unevaluated, and `check --strict` exits 4 on it.
- Input the toolkit cannot process does not abort the audit: the record is written with `status: "degraded"` and an `input_errors` list. A value that cannot be banded is dropped, and never appears raw in the log or inside an error message.
- The decision object has an allowlist of its own, so an identifier a caller attaches to it is dropped before the record reaches a log that cannot be edited afterwards.
- Timestamps must not run backwards; a clock stepping backwards is clamped forward and counted.
- Concurrent writers are serialised on a lock file (POSIX and Windows), and blocks committed by another writer are checked, signature included, before this writer links onto them. Appends to a chain that failed verification are refused.
- A record whose write was cut short is discarded on load, reported as a warning, and cut from the file before the next append; every complete record before it is kept.
- Emitting a checkpoint or a proof refuses on a chain that does not verify.

### Tooling
- CLI: `demo`, `audit`, `batch`, `verify`, `check`, `summary`, `report`, `checkpoint`, `prove`, `verify-proof`, `reset`, with meaningful exit codes and relocatable state via `--state-dir`.
- Installable package with a `decision-audit` entry point and `py.typed`. CI covers the suite on Python 3.10, 3.12 and 3.14, plus lint, types, packaging and the native-crypto path.

### Known limits
- No key rotation: one signing key for the life of the chain.
- No external time anchoring: timestamps come from the writer's clock.
- Drift covers mean shifts only; changes in variance and correlation are not detected.

See **What it is not** in `README.md` for what none of this closes.
