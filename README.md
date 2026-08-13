# Decision Audit Toolkit

[![Tests](https://github.com/CiavaLabs/Decision-Audit-Toolkit/actions/workflows/ci.yml/badge.svg)](https://github.com/CiavaLabs/Decision-Audit-Toolkit/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2FCiavaLabs%2FDecision-Audit-Toolkit%2Fmain%2F.github%2Fbadges%2Fcoverage.json)](#quick-start)
[![Version](https://img.shields.io/github/v/tag/CiavaLabs/Decision-Audit-Toolkit?label=version)](https://github.com/CiavaLabs/Decision-Audit-Toolkit/releases)
[![Python](https://img.shields.io/badge/python-%E2%89%A5%203.10-blue)](#quick-start)
[![License](https://img.shields.io/github/license/CiavaLabs/Decision-Audit-Toolkit)](LICENSE)

A dependency-free Python toolkit for auditing automated decisions. Whatever
produced the decision — an ML model, a scorecard, a human rule — it is checked
against a declarative policy, monitored for population drift, redacted, and
appended to a tamper-evident log that can be verified and reported on later.

The bundled example is a toy retail mortgage flow. Nothing in the core is
mortgage-specific: policies are JSON, the decision source is pluggable, and the
CSV replay accepts arbitrary column mappings.

Everything runs on the Python standard library. Python 3.10+.

The reasoning behind the design is in [ARCHITECTURE.md](ARCHITECTURE.md).

## What it does

- **Policy constraints** — declarative JSON rules (`ratio_max`, `ratio_min`,
  `lte_field`, `value_max`, `value_min`, `positive`, `in_set`, and the
  combinators `all_of`, `any_of`, `not`) evaluated as pure functions, with no
  `eval()`. A field a rule needs but the context does not carry is reported as a
  violation of severity `error`.
- **Tamper-evident log** — a linear hash chain whose block hashes are signed, by
  default with Ed25519, so a third party holding the public key can verify the
  log without being able to forge it. Storage is append-only JSON Lines written
  with fsync; concurrent writers are serialised on a lock file, and a write cut
  short by a crash costs its own record and nothing before it.
- **Proofs about one record** — a Merkle tree (RFC 6962) over the same blocks
  gives inclusion proofs (this decision is in the log described by a signed tree
  head, disclosing no other record) and consistency proofs (a later log still
  carries an earlier one as an unchanged prefix). Both are self-contained JSON,
  verifiable with the public key alone.
- **Signed checkpoints** — a compact signed statement of the chain head and the
  Merkle root, to store out of band. Checking it later exposes truncation or
  rewriting even by someone holding the signing key.
- **Redaction** — sensitive amounts are coarsened to configurable bands, an
  explicit clear-list is kept as-is, and every other field is dropped with the
  dropped names recorded on the record. The decision object has an allowlist of
  its own.
- **Every decision leaves a record** — input the toolkit cannot process does not
  abort the audit: the record is written with `status: "degraded"` and an
  `input_errors` list saying what could not be evaluated. A value that cannot be
  banded is dropped, and never appears raw in the log or in an error message.
- **Drift detection** — a per-feature two-sample z statistic (pooled variance)
  between a reference and a sliding test window, aggregated by RMS, with the
  threshold in sigma units. The windows persist between runs, so drift works
  under one-decision-per-invocation integration and across several writers. Mean
  shifts only: changes in variance and correlation are not covered.
- **Fairness metrics** — per segment: model and final approval rates with 95%
  Wilson confidence intervals, violation rate, the share of the segment's
  approvals that policy reversed, and average score; plus the approval-rate span
  and the least-to-most-approved ratio across segments. Groups below a
  configurable minimum are reported and kept out of the comparison.
- **Portfolio thresholds** — declarative rules evaluated over the whole
  population. `check` exits non-zero on a breach.
- **Reports** — a portfolio summary as JSON, carrying the integrity verdict for
  the log it describes, and a self-contained HTML report.

## What it is not

- **Not a compliance product.** It is a compact reference implementation for
  learning and prototyping audit pipelines.
- **Not a blockchain.** The log is a local file: no consensus, no proof of work,
  no distribution.
- **Not audited cryptography.** The Ed25519 implementation follows RFC 8032 and
  passes the RFC test vectors. It is pure Python: not constant-time, not
  side-channel hardened, and slow compared to native libraries. Key files are
  plain files with restrictive permissions, never an HSM or KMS.
- **Not differential privacy.** Redaction is banding plus an allowlist: raw
  values never reach the log, and banded values remain attributes of the record.
- **No key rotation.** One signing key, for the life of the chain. A log meant to
  run for years needs key epochs and a signed transition between them, with
  blocks recording which key signed them. That is not implemented.
- **No external time anchoring.** Timestamps come from the writer's clock.
  Verification requires them non-decreasing and clamps a clock that steps
  backwards; nothing here proves *when* a record was written to someone who does
  not trust the writer. RFC 3161 timestamping would, and needs DER/ASN.1 handling
  absent from the standard library. Publishing signed tree heads somewhere
  append-only is the practical substitute, and is what `prove --head` is for.
- **No trained model included.** The demo decision engine
  (`decision_audit/model.py`) is a hand-written, transparent scorecard, present
  so the demos have something to audit.

## Quick start

```bash
git clone https://github.com/CiavaLabs/Decision-Audit-Toolkit.git
cd Decision-Audit-Toolkit

python3 -m decision_audit demo
python3 -m decision_audit batch

python3 -m decision_audit verify

python3 -m decision_audit summary
python3 -m decision_audit report --out audit_report.html

python3 -m unittest discover -s tests
```

`demo` is a guided walkthrough covering redaction, a rejection, a policy override
and a drift alert. `batch` replays the sample dataset, whose two populations put
drift at the switches. `verify` exits 1 on an invalid chain; `summary` and
`report` describe the stored log.

Installing the package provides the `decision-audit` command:

```bash
pip install -e .
decision-audit demo
```

## CLI

| Command | Description | Exit codes |
|---------|-------------|------------|
| `demo` | Guided mortgage walkthrough, writes real records | 0 ok |
| `audit` | Audit decisions from JSON on stdin or a file (`--input`) | 0 ok, 2 bad input, 3 logged but degraded |
| `batch` | Replay a CSV into the audit log (`--data-path`, `--field-map`) | 0 ok, 2 data error |
| `verify` | Verify the stored chain (`--json`, `--full`, `--stream`) | 0 valid or no state, 1 invalid |
| `check` | Evaluate portfolio thresholds (`--json`, `--strict`, `--stream`) | 0 pass, 1 breached or chain invalid, 2 bad policy, 4 `--strict` and incomplete |
| `summary` | Portfolio summary as JSON (`--stream`) | 0 ok, 1 chain invalid |
| `report` | Write an HTML report (`--out`) or print JSON (`--json`) | 0 |
| `checkpoint` | Emit a signed head-of-chain statement, or `--check FILE` | 0 ok, 1 mismatch or chain invalid |
| `prove` | Emit a proof: `--index N`, `--since FILE`, or `--head` | 0 ok, 1 chain invalid, 2 bad request |
| `verify-proof` | Check a proof file; needs only the public key | 0 ok, 1 invalid |
| `reset` | Delete the state directory's chain and keys (`--yes`) | 0 |

Exit code 1 also means a command found the stored chain invalid: a writing
command refused to append to it, and a reading command refused to describe it as
sound. `summary`, `check`, `prove` and `checkpoint` all verify before they
answer.

Exit code 3 from `audit` means every record was written and at least one is
`degraded`: the decision is in the log, some part of it could not be evaluated,
and `input_errors` on the result says which. `audit` validates its whole input
before writing anything, so a malformed item leaves no earlier ones committed.

Exit code 4 comes only from `check --strict` and means no rule was breached while
not every rule could be evaluated — typically because no two segments reached
`min_group_size`. Without `--strict` that is a pass with a note.

Global options belong to the tool, so they precede the subcommand:
`decision-audit --public-key k.pub verify`.

| Option | Effect |
|--------|--------|
| `--state-dir` | Directory holding the chain, keys and drift windows (default `audit_state/`) |
| `--policy-profile`, `--policy-config` | Registered constraint profile, or a JSON file that overrides it |
| `--aggregate-profile`, `--aggregate-config` | Registered portfolio profile (`financial_basic` ships), or a JSON file |
| `--scheme {ed25519,hmac}` | Signature scheme for new chains; existing chains keep the scheme they were created with |
| `--key-path`, `--public-key` | Key files outside the state directory |

Read-only commands create no state on disk, so `--state-dir` can point at a
per-session directory. `reset` removes only files the state directory owns: a key
file named with `--key-path` or `--public-key` is left alone.

## Library usage

```python
from decision_audit import AuditOrchestrator, Config

config = Config(
    drift_window_size=50,     # observations in the reference window
    drift_threshold=3.0,      # sigma units
    state_dir="audit_state",
)
orch = AuditOrchestrator(config)

decision = {"decision": "APPROVE", "score": 0.42, "reasons": ["LTV <= 70%"]}
context = {
    "loan_amount": 150000,
    "property_value": 200000,
    "monthly_debt": 1000,
    "monthly_income": 6000,
    "marginal_var": 0.5,
    "var_limit": 1.0,
    "segment": "prime",           # logged in clear, used for fairness grouping
    "features": [150000, 200000, 1000, 6000, 0.5],  # drift input, never logged
}

result = orch.audit_decision(decision, context)
print(result["final_outcome"])        # APPROVE, or BLOCKED_BY_POLICY
print(orch.verify_integrity())        # chain status and counts
print(orch.get_portfolio_summary())   # aggregates incl. fairness metrics
```

The audit flow per decision: constraint checks → drift update (if `features` is
present) → redaction → append to the chain. Policy violations override model
approvals (`final_outcome: BLOCKED_BY_POLICY`); rejections and reviews stand as
the model issued them.

## Policies

Constraints ship as two profiles: `financial_basic` (LTV ≤ 80%, DSR ≤ 35%, VaR
within limit, positive amounts) and `financial_strict` (tighter limits plus a
minimum income). `policies/financial_basic.json` and
`policies/financial_strict.json` carry the same rules as the built-in registry.
`--policy-config` (or `Config.policy_config_path`) accepts any file with that
schema:

```json
{
  "constraints": [
    {"id": "ltv_limit", "type": "ratio_max", "numerator": "loan_amount",
     "denominator": "property_value", "max": 0.8,
     "severity": "high", "description": "Loan-to-value ratio must be <= 80%"}
  ]
}
```

`register_constraint_type(name, builder)` adds rule types without editing the
package. The builder is Python the operator already trusts and the JSON stays
data, so there is still no `eval`.

A malformed rule is refused when the file is read, with a message naming the rule
and what it lacks.

A rule that names a field the context does not carry reports a violation of
severity `error`. The one field that may be absent is the right-hand side of
`lte_field`, which falls back to its declared `other_default`. In a combination,
a branch that cannot be evaluated does not fail the rule and does not override a
branch that settled the question: `all_of` reports the violation if any branch
failed and "unknown" only if none did, `any_of` passes if any branch was
satisfied and "unknown" only if none was.

### Portfolio thresholds

Constraints see one decision. Fairness and drift are properties of a population,
so they get their own declarative layer — `policies/aggregate_strict.json` is a
worked example, tighter than the `financial_basic` profile that ships:

```json
{
  "aggregate_rules": [
    {"id": "four_fifths", "type": "min_approval_ratio", "min": 0.8,
     "min_group_size": 50, "severity": "critical",
     "description": "The least-approved segment must reach 80% of the most-approved rate"}
  ]
}
```

Types: `max_approval_span`, `min_approval_ratio`, `max_override_rate_gap`,
`max_violation_rate`, `max_anomaly_rate`, `max_degraded_rate`, extensible via
`register_aggregate_rule`. `decision-audit check` evaluates them and exits 1 on a
breach, or on a log that does not verify. The HTML report carries the same table.

A rule is validated when the file is read: a threshold that is missing or is not
a number is exit code 2 and a message naming the rule. A rule the *data* cannot
support is reported as unevaluated instead, and `--strict` exits 4 on it.

## Redaction defaults

| Field | Treatment |
|-------|-----------|
| `loan_amount`, `property_value` | banded to 10 000 |
| `monthly_income`, `monthly_debt` | banded to 500 |
| `period`, `segment`, `marginal_var`, `var_limit` | logged as-is |
| everything else (ids, notes, `features`, …) | dropped, names recorded |

Bands and the clear-list are configurable (`Config.banded_fields`,
`Config.clear_fields`). `segment` and `period` are kept in clear because the
fairness and drift breakdowns need them; they are coarse, non-identifying
categories.

## Signatures and checkpoints

New chains are signed with Ed25519: the private seed (`ed25519_key.bin`, created
lazily on first signing) signs each block, the public key (`ed25519_key.pub`)
verifies. A third party auditing the log needs the chain file and the public key
— enough to verify everything
(`decision-audit --public-key ed25519_key.pub verify`) and to forge nothing.
`--scheme hmac` selects the symmetric scheme instead, where the single shared key
both signs and verifies.

Per-block signatures cannot expose a wholesale rewrite by someone who also holds
the private key. A checkpoint stored out of band covers that:

```bash
python3 -m decision_audit checkpoint > checkpoint.json   # save elsewhere
# ... later ...
python3 -m decision_audit checkpoint --check checkpoint.json
```

`--check` verifies the checkpoint signature, that the chain is at least as long
as it was when the checkpoint was taken, and that the Merkle root over the
checkpointed prefix still matches; truncated or rewritten history fails with exit
code 1. Emitting a checkpoint refuses on a chain that does not verify.

A checkpoint that carries no Merkle root still passes on the checks it does
support, with a warning saying only its head block could be verified. That is a
weaker guarantee, and it is reported differently from a failed verification.

## Proving one record

Verifying the chain establishes that the log was not edited, for someone holding
all of it. A Merkle tree over the same blocks proves a single decision on its
own:

```bash
# the log holder, with the chain
python3 -m decision_audit prove --index 137 --out record137.json

# anyone else, with the public key and nothing else
python3 -m decision_audit --state-dir ./verifier \
    --public-key ed25519_key.pub verify-proof record137.json
```

On a 250-record log that proof is 2 KB against 200 KB of chain, and the gap
widens with size: at 100 000 records an inclusion proof is 17 hashes, 544 bytes,
whatever the log has grown to. It contains the one record it is about and a list
of opaque sibling hashes — no other record's content, ids or values.

Verification recomputes the record's block hash from the record itself, so a
proof binds to what the decision actually says. Editing the record fails;
repairing its hash to match moves the failure to the tree.

Showing that nothing behind a record was rewritten means keeping a tree head and
asking for a consistency proof later:

```bash
python3 -m decision_audit prove --head --out head_march.json   # store off-site
# ... months later ...
python3 -m decision_audit prove --since head_march.json --out grew.json
python3 -m decision_audit verify-proof grew.json
```

None of this constrains someone who holds the signing key *and* the log: they can
rewrite both. Storing a tree head beyond their reach is what closes that, and is
the reason checkpoints exist.

## State and reproducibility

The chain (`chain.jsonl`, one signed block per line) and the key files live in
the state directory and persist across runs, so `verify`, `summary` and `report`
operate on everything ever logged there. The drift detector's windows live there
too, in `drift_state.json`: they cannot be rebuilt from the log, because
`features` are dropped in redaction and never written to it. That file carries no
signature and sits outside the chain — losing it costs the detector its warm-up
and nothing else, and editing it cannot alter a recorded decision.

`reset` deletes all of it, along with the `chain.jsonl.lock` file writers
coordinate on. It asks first when run from a terminal, since it removes both the
log and the key that proves it was ever signed; `--yes` skips the prompt, and a
non-interactive run never sees one.

Timestamps come from `Config.clock`; injecting a fixed clock makes runs
byte-for-byte reproducible, as the test suite does.

## Adapting it to another dataset

1. Write a policy JSON for the domain and pass `--policy-config`.
2. Replay a CSV with `batch --data-path file.csv --field-map map.json`, where the
   map is `{"context_field": "csv_column"}` for any header that differs from the
   defaults. A row missing one of the amounts the policies are written against is
   skipped and counted; substituting a zero would invent a figure and then record
   it as a policy violation.
3. Replace the demo scorecard: call `audit_decision(decision, context)` with the
   output of any model or rule engine — the toolkit expects `decision` (label)
   and optionally `score`/`reasons`.
4. Integrate from any language via the `audit` command, which reads one decision
   (or a list) as JSON and prints the audit result:

```bash
echo '{"decision": {"decision": "APPROVE", "score": 0.42},
       "context": {"loan_amount": 150000, "property_value": 200000,
                   "monthly_debt": 1000, "monthly_income": 6000,
                   "marginal_var": 0.5, "var_limit": 1.0, "segment": "prime"}}' \
  | python3 -m decision_audit audit
```

## Verification cost

Hashing is cheap and signature verification is not, so the default pass
recomputes **every** block hash and checks **every** link, while verifying the
signature on the **head block only**. That detects any modification of recorded
content: a block hash covers the previous block's hash, so the head hash is a
commitment to the entire history. Editing a record forces the head hash to change
— immediately as a hash mismatch or a broken link, or after the attacker
recomputes the whole cascade — and a changed head hash needs a signature nobody
without the key can produce.

Measured on one machine with the pure-Python backend, opening a chain and
appending one record:

| blocks | signature per block | head signature only |
|-------:|--------------------:|--------------------:|
| 100 | 0.63 s | 0.020 s |
| 400 | 2.57 s | 0.034 s |
| 800 | 5.22 s | 0.054 s |
| 100 000 | ~11 min (extrapolated) | ~7 s (extrapolated) |

`verify --full` additionally checks every block's own signature. The signature
field is not covered by the block hash, so tampering with one in the middle of
the chain — which changes no recorded content — is the one thing the default pass
does not report. Neither mode detects truncation of the newest blocks: every
block was signed as a valid head when it was written. That is what checkpoints
are for.

### Reading a log larger than memory

`verify --stream` reads the file one record at a time instead of loading it,
checking the same things and computing the same Merkle root with a fixed amount
of state. On a 20 000-record chain (13.5 MiB) the two paths agree on the verdict,
the errors, the warnings, the counts and the root; peak memory goes from 113 MiB
to 0.1 MiB, and it runs about twice as fast. The tests assert that agreement word
for word on the error messages, including a file with no header, one with a
header line spliced into the middle, one with a torn final record and one that
cannot be read at all.

`summary --stream` and `check --stream` do the same. The summary is pure
aggregation, so none of it needs more than one record in hand and it folds into
the same single pass that verifies. The accumulation lives in `portfolio.py` and
is shared, so the loaded and streamed summaries are the same arithmetic.
Verifying and summarising together, on 20 000 records of a narrower shape
(8.2 MiB on disk):

| | peak memory | time |
|---|---:|---:|
| loaded | 68.5 MiB | 7.5 s |
| streamed | 0.23 MiB | 4.1 s |

The one part of a summary that does not fit in constant space is the list of
drift anomalies, which grows with the number of alerts. It is capped at 1000
rows, with `anomaly_audits_truncated` reporting what was left out; the total is
always exact in `with_anomaly`.

The write path and the proof path still load the chain: appending needs the head
and a proof needs the tree. `report` loads it too, since it renders the whole
thing at once.

### Optional native Ed25519

The bundled pure-Python implementation is the default and always works. It holds
the multiples of the base point once instead of recomputing them per signature,
and caches the public key it derives from a seed. An installed `cryptography` or
`PyNaCl` is used in its place:

| backend | sign | verify |
|---------|-----:|-------:|
| python (bundled) | 670/s | 173/s |
| cryptography | 9 250/s | 6 160/s |
| pynacl | 13 940/s | 10 760/s |

Neither is a dependency and neither changes the output: Ed25519 signatures are
deterministic, so every backend produces the same bytes for the same seed and
message, and a chain written on a machine with a native library verifies on one
without it. CI checks exactly that. Set `DECISION_AUDIT_ED25519_BACKEND` to
`python`, `cryptography` or `pynacl` to pin one; an unavailable name is an error,
never a silent downgrade.

## Alternatives

Every pillar here exists as a deeper, dedicated tool: Open Policy Agent for
policy engines, Evidently or NannyML for drift monitoring, Fairlearn or Aequitas
for fairness analysis, immudb or transparency logs such as sigstore Rekor for
tamper-evident storage. Those are the ones to reach for at production depth. This
project's niche is the combination in one small dependency-free codebase, short
enough to be read end to end — which is occasionally what an audit trail requires
of its own tooling.

## Versioning

Semantic-ish versioning, single source in `decision_audit/_version.py`. See
[CHANGELOG.md](CHANGELOG.md).

## License

MIT — see [LICENSE](LICENSE).
