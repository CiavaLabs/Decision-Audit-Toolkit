# Architecture

This file records why the code is shaped the way it is. Each entry states a
decision and the failure it avoids, so a change can be weighed against what the
current design was protecting.

[README.md](README.md) documents behaviour: the commands, the guarantees and the
refusals a caller works with.

Entries marked **Invariant** are load-bearing for correctness or security. An
edit that breaks one does not fail loudly.

## The log

- **Invariant — the block hash covers index, timestamp, data and `prev_hash`,
  and nothing else.** The signature sits outside it deliberately: a hash cannot
  cover the signature over itself. The consequence is that editing a signature
  in the middle of the chain changes no hash and no link, which is why
  `verify --full` exists and why the default pass cannot report it.
- **Invariant — the head signature commits to the whole history.** Each block
  hash folds in the previous one, so editing any record forces the head hash to
  change, and a changed head hash needs a signature nobody without the key can
  produce. This is what makes head-only verification sound, and what keeps
  opening a long chain to seconds.
- **A clock stepping backwards is clamped forward and counted.** NTP correction
  and restored snapshots both produce it. Writing the reading as it came would
  put a timestamp below its predecessor into an append-only file, and
  verification would reject that log for the rest of its life.
- **A torn final record is discarded on load.** Every complete record ends with a
  newline, so trailing bytes without one belong to an append that never returned
  to its caller. Nothing acknowledged is lost.
- **Invariant — the file is truncated to the last complete record before an
  append.** Opening in append mode seeks past a torn tail and splices the next
  record onto a partial line, which produces two unreadable records where there
  was one.
- **Blocks committed by other writers are checked before this writer links onto
  them** — hash, index, link and signature. Checking the links alone would let a
  writer extend a forged block and report success.
- **`node_from_dict` types every field where the record is parsed.** The chain
  file is the one input this package cannot vouch for. A string timestamp
  reaching the ordering comparison in `verify_integrity` raises `TypeError`,
  which is a crash where the answer should have been "this block does not
  verify".
- **Whether the stored chain verifies is settled on the first append.** Only a
  writer needs the answer, and resolving it on load made every read-only command
  pay for a pass over a log it never used.
- **The header line pins the signature scheme.** Appending under a different one
  mixes signatures in a single file, and the result reads as tampering.
- **Records are written with `newline="\n"`.** The log is meant to be handed to a
  third party byte for byte, and a platform-dependent line ending changes the
  bytes without changing the content.

## Proofs and checkpoints

- **Invariant — Merkle leaves are recomputed from block content.** The stored
  `hash` field is never consulted. A record edited without its stored hash being
  repaired then produces a tree that no longer matches the signed root; read from
  the file, the tree would quietly agree with it.
- **Invariant — inclusion verification recomputes the block hash from the record
  in the proof.** Otherwise the proof binds to a hash, and any content could be
  attached to it.
- **The 0x00 and 0x01 prefixes are RFC 6962's domain separation.** Without them a
  leaf can be presented as an interior node, which lets one tree be read as a
  different tree with the same root.
- **The Merkle tree is cached under `(length, head hash)`.** A chain reloaded
  after a rewrite can have the same length and different content.
- **Checkpoints answer a question per-block signatures cannot.** Someone holding
  the signing key and the log can rewrite both and re-sign. A signed statement of
  the head and the prefix root, stored where they cannot reach it, is what turns
  truncation and rewriting into detectable events.
- **A checkpoint carrying no Merkle root passes with a warning.** Every check
  available to it ran and succeeded; the guarantee is narrower, and reporting a
  successful verification as a failure is how alarms stop being read.

## Policy evaluation

- **Invariant — a field a rule needs but the context does not carry is a
  violation of severity `error`.** Reading an absent field as zero lets a typo in
  a field name satisfy the constraint it was meant to enforce.
- **Invariant — `all_of` and `any_of` collect their unevaluated branches instead
  of stopping at the first.** A branch that could not be evaluated does not fail
  the rule and does not override a branch that settled the question, so the
  verdict does not depend on the order the rules happen to be written in.
- **Rule types declare the threshold keys they need, and the policy is validated
  when it is read.** A threshold discovered at evaluation time raises `KeyError`,
  which is caught and reported as "not evaluated" — and an unevaluated rule does
  not breach, so `decision-audit check` would exit 0 on a policy that was
  enforcing nothing. `{"type": "min_approval_ratio", "minimum": 0.8}`, one letter
  wrong, is the whole failure.
- **A rule the data cannot support is reported as unevaluated.** Fewer than two
  comparable segments is a fact about the portfolio, and `--strict` is for
  pipelines that will not accept a partial answer.

## Drift

- **Invariant — the windows are read and written under the chain's own lock.**
  They are shared state. Two writers each holding a private copy overwrite each
  other's observations.
- **The windows persist because they cannot be rebuilt.** `features` are dropped
  in redaction and never reach the log, so a detector starting from memory alone
  never fills a reference window under one-decision-per-invocation integration,
  and reports no drift at all. `drift_state.json` is working state: it carries no
  signature, sits outside the chain, and editing it cannot alter a recorded
  decision.
- **State recorded under different window settings is refused.** A reference
  window of 50 read as one of 20 makes the detector report on a population it
  never saw.
- **An empty feature vector is refused before it reaches a window.** It would fix
  the feature count at zero, and every real observation afterwards would be
  rejected for the wrong width — a detector permanently unable to see anything,
  saved to disk.
- **A feature whose pooled variance is zero while its mean moved scores 1e6.**
  The shift is definite and the statistic is unbounded there; a large finite
  value keeps the record valid JSON, which an infinity would not be.

## Redaction

- **Invariant — the decision object carries its own allowlist.** It is logged in
  clear. Without one, an identifier a caller attaches to a decision is written
  verbatim into a log that by design cannot be edited afterwards.
- **Bands are computed in decimal.** Binary floating point puts a value sitting
  exactly on a band edge in the band below it.
- **A value that cannot be banded is dropped, and the error names the field
  only.** Quoting the value back would put the raw figure in the record that
  redaction exists to keep it out of.

## Reading without loading

- **Invariant — the streamed pass and the loaded pass agree on the verdict, the
  errors and their order.** The tests assert this word for word, including on a
  file with no header, a header spliced into the middle, a torn final record and
  a file that cannot be read at all. A divergence lets `verify --stream` pass a
  log that `verify` refuses.
- **The streaming root merges only equal-sized neighbours.** That is what
  reproduces the largest-power-of-two split RFC 6962 specifies, and it is why the
  two paths produce the same root from a fixed amount of state.
- **Coverage has to trace subprocesses.** `tests/test_cli.py` drives the command
  the way a user does, through `subprocess.run`, which is the only way to check
  argv parsing, exit codes and what actually reaches stdout. Measured without
  tracing into those children, `cli.py` and `demo.py` read as entirely uncovered
  — 470 of 2464 statements, and a headline figure 19 points below the truth.
- **The constant-memory test compares the minimum of several runs, over prefixes
  of one chain.** A traced peak is noise upward only: allocation the run happened
  to need, never less than what it truly used, so the minimum over repetitions is
  the stable floor and a single sample runs three times high often enough to fail
  a threshold on a green tree. Prefixes keep the setup to one signing pass, and a
  prefix verifies on its own because every block was signed as a valid head when
  it was written.

## Signing

- **Invariant — every backend produces identical bytes.** Ed25519 signatures are
  deterministic, so a chain written on a machine with a native library verifies
  on one without it. CI runs the suite under each backend on its own to keep it
  that way.
- **A pinned backend that is unavailable is an error.** Someone who set
  `DECISION_AUDIT_ED25519_BACKEND` wants to know it was not used.
- **The backend is resolved on first use.** Selecting at import time turns an
  unusable value in the environment into a traceback from
  `import decision_audit`, where it should surface as a message the CLI reports.
- **Invariant — key files are created with their mode already set, and fsynced.**
  Opening first and calling `chmod` after leaves the key readable under the
  umask in between. Without the fsync, a power loss can leave a signed chain
  whose key never reached disk, which is a log nobody can verify.
- **The pure-Python implementation is not constant-time.** It follows RFC 8032
  and passes the section 7.1 vectors; it is not hardened against side channels.

## Concurrency

- **Appending is a read-modify-write across processes.** A writer has to see
  every block other processes committed before it computes its own index and
  `prev_hash`, so the chain serialises appends on a lock file beside the log. A
  thread lock cannot provide that.
- **A platform offering neither `fcntl.flock` nor `msvcrt.locking` degrades to a
  no-op**, and concurrent appends from separate processes are unsafe there.

## Fairness

- **Approval rates carry Wilson intervals.** Rates here sit near 0 or 1 and
  groups are routinely small, which is where the textbook normal approximation
  produces intervals running past 0 or 1.
- **Below two comparable groups the approval span is absent.** A computed 0.0
  reads as "no disparity found", which is a different claim from "there was
  nothing to compare".
