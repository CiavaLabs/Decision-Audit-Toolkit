import argparse
import contextlib
import json
import sys
from pathlib import Path

from ._version import __version__
from .chain import ChainIntegrityError
from .config import Config
from .locking import lock_path_for
from .orchestrator import AuditOrchestrator
from .utils import loads_strict

EXIT_INCOMPLETE = 4


def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        prog="decision-audit",
        description="Audit automated decisions: policy checks, tamper-evident log, drift and fairness metrics.")
    p.add_argument("--version", action="version", version=f"decision-audit {__version__}")
    p.add_argument("--state-dir", default="audit_state", help="Directory holding the chain and keys")
    p.add_argument("--policy-profile", default="financial_basic", help="Registered policy profile name")
    p.add_argument("--policy-config", help="Path to a JSON policy file (overrides --policy-profile)")
    p.add_argument("--aggregate-profile", default="financial_basic",
                   help="Registered portfolio-threshold profile name")
    p.add_argument("--aggregate-config",
                   help="Path to a JSON aggregate-rules file (overrides --aggregate-profile)")
    p.add_argument("--scheme", choices=("ed25519", "hmac"), default="ed25519",
                   help="Signature scheme for new chains (existing chains keep theirs)")
    p.add_argument("--key-path", help="Signing key file (default: <state-dir>/<scheme>_key.bin)")
    p.add_argument("--public-key", help="Ed25519 public key file for verification only")
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("demo", help="Run the guided mortgage demo")
    audit_cmd = sub.add_parser(
        "audit", help="Audit decisions from JSON (file or stdin) and append them to the log")
    audit_cmd.add_argument("--input", default="-",
                           help="JSON file with {decision, context}, or a list of them; - for stdin")
    batch = sub.add_parser("batch", help="Replay a CSV of decisions into the audit log")
    batch.add_argument("--data-path", default="data/sample_mortgages.csv", help="CSV dataset to replay")
    batch.add_argument("--field-map", help="JSON file mapping context fields to CSV columns")
    verify = sub.add_parser("verify", help="Verify the stored chain; exit code 1 if invalid")
    verify.add_argument("--json", action="store_true", help="Machine-readable output")
    verify.add_argument("--full", action="store_true",
                        help="Verify every block's signature, not just the head's "
                             "(costs one signature check per block)")
    verify.add_argument("--stream", action="store_true",
                        help="Read the log one record at a time instead of loading "
                             "it, for chains larger than memory")
    summary = sub.add_parser(
        "summary", help="Print a portfolio summary from the stored chain (JSON)")
    summary.add_argument("--stream", action="store_true",
                         help="Read the log one record at a time instead of loading "
                              "it, for chains larger than memory")
    report = sub.add_parser("report", help="Build a report from the stored chain")
    report.add_argument("--out", default="audit_report.html", help="Output HTML file")
    report.add_argument("--json", action="store_true", help="Print the report as JSON to stdout instead")
    checkpoint = sub.add_parser(
        "checkpoint", help="Emit a signed statement of the chain head, or check a saved one")
    checkpoint.add_argument("--check", metavar="FILE",
                            help="Verify a saved checkpoint against the stored chain; exit 1 on mismatch")
    check = sub.add_parser(
        "check", help="Evaluate portfolio-level thresholds (fairness gaps, drift rate)")
    check.add_argument("--json", action="store_true", help="Machine-readable output")
    check.add_argument("--strict", action="store_true",
                       help=f"Exit {EXIT_INCOMPLETE} when a rule could not be "
                            "evaluated, instead of passing on a partial answer")
    check.add_argument("--stream", action="store_true",
                       help="Read the log one record at a time instead of loading "
                            "it, for chains larger than memory")
    prove = sub.add_parser(
        "prove", help="Emit a proof about the log that is verifiable without it")
    prove_what = prove.add_mutually_exclusive_group(required=True)
    prove_what.add_argument("--index", type=int, metavar="N",
                            help="Prove record N is in the log (inclusion proof)")
    prove_what.add_argument("--since", metavar="FILE",
                            help="Prove the log still extends an earlier tree head "
                                 "or checkpoint (consistency proof)")
    prove_what.add_argument("--head", action="store_true",
                            help="Emit a signed tree head describing the log as it stands")
    prove.add_argument("--out", help="Write to a file instead of stdout")
    checked = sub.add_parser(
        "verify-proof", help="Check a proof file; needs only the public key, not the log")
    checked.add_argument("proof", help="Proof file emitted by `prove`")
    reset = sub.add_parser("reset", help="Delete the stored chain and keys")
    reset.add_argument("--yes", "-y", action="store_true",
                       help="Skip the confirmation prompt")

    args = p.parse_args(argv)
    config = Config(
        state_dir=args.state_dir,
        policy_profile=args.policy_profile,
        policy_config_path=args.policy_config,
        aggregate_profile=args.aggregate_profile,
        aggregate_config_path=args.aggregate_config,
        signature_scheme=args.scheme,
        key_path=args.key_path,
        public_key_path=args.public_key
    )

    try:
        if args.command == "verify":
            return _cmd_verify(config, as_json=args.json, full=args.full,
                               stream=args.stream)
        if args.command == "summary":
            return _cmd_summary(config, stream=args.stream)
        if args.command == "reset":
            return _cmd_reset(config, assume_yes=args.yes)
        if args.command == "report":
            return _cmd_report(config, out_path=args.out, as_json=args.json)
        if args.command == "checkpoint":
            return _cmd_checkpoint(config, check_path=args.check)
        if args.command == "check":
            return _cmd_check(config, as_json=args.json, strict=args.strict,
                              stream=args.stream)
        if args.command == "prove":
            return _cmd_prove(config, index=args.index, since=args.since,
                              head=args.head, out_path=args.out)
        if args.command == "verify-proof":
            return _cmd_verify_proof(config, proof_path=args.proof)
        if args.command == "audit":
            return _cmd_audit(config, input_path=args.input)
        if args.command == "batch":
            from .demo import load_field_map, run_batch_from_csv
            run_batch_from_csv(args.data_path, config=config,
                               field_map=load_field_map(args.field_map))
            return 0
        from .demo import main as demo_main
        demo_main(config)
        return 0
    except ChainIntegrityError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except (ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2

def _signer_for_stored_chain(config: Config, chain_file: Path):
    from .chain import detect_chain_scheme
    from .crypto import make_signer
    scheme = detect_chain_scheme(chain_file) or config.signature_scheme
    return make_signer(scheme,
                       key_path=config.resolved_key_path(scheme),
                       public_key_path=config.resolved_public_key_path(scheme))

def _stream_verify(config: Config, chain_file: Path, *, full: bool = False,
                   summary=None) -> dict:
    from . import ed25519
    from .streaming import verify_stream
    signer = _signer_for_stored_chain(config, chain_file)
    report = verify_stream(chain_file, signer, full=full, summary=summary)
    report["version"] = __version__
    report["scheme"] = signer.scheme
    report["policy"] = config.policy_config_path or config.policy_profile
    if signer.scheme == "ed25519":
        report["ed25519_backend"] = ed25519.active_backend()
    return report

def _cmd_verify(config: Config, as_json: bool, full: bool = False,
                stream: bool = False) -> int:
    chain_file = Path(config.resolved_chain_path())
    if not chain_file.exists():
        print(f"No audit state at {chain_file}; nothing to verify.")
        return 0
    if stream:
        report = _stream_verify(config, chain_file, full=full)
    else:
        report = AuditOrchestrator(config).verify_integrity(full=full)
    if as_json:
        print(json.dumps(report, indent=2))
    else:
        status = "VALID" if report["valid"] else "INVALID"
        print(f"Chain: {status} ({report['blocks']} blocks, "
              f"signatures: {report['signature_check']})")
        for warning in report["warnings"]:
            print(f"  ! {warning}")
        for err in report["errors"]:
            print(f"  - {err}")
    return 0 if report["valid"] else 1

def _portfolio_from_stream(config: Config, chain_file: Path) -> tuple[dict, dict]:
    from .portfolio import PortfolioAccumulator
    accumulator = PortfolioAccumulator(
        min_group_size=config.fairness_min_group_size)
    integrity = _stream_verify(config, chain_file, summary=accumulator)
    return integrity, accumulator.result()

def _cmd_summary(config: Config, stream: bool = False) -> int:
    chain_file = Path(config.resolved_chain_path())
    if stream and chain_file.exists():
        integrity, summary = _portfolio_from_stream(config, chain_file)
    else:
        orch = AuditOrchestrator(config)
        integrity, summary = orch.verify_integrity(), orch.get_portfolio_summary()
    summary["integrity"] = {
        "valid": integrity["valid"],
        "errors": integrity["errors"],
        "signature_check": integrity["signature_check"],
    }
    print(json.dumps(summary, indent=2))
    return 0 if integrity["valid"] else 1

def _cmd_report(config: Config, out_path: str, as_json: bool) -> int:
    from .report import build_report, render_html
    report = build_report(AuditOrchestrator(config))
    if as_json:
        print(json.dumps(report, indent=2))
        return 0
    Path(out_path).write_text(render_html(report), encoding="utf-8")
    print(f"Report written to {out_path}")
    return 0

def _cmd_audit(config: Config, input_path: str) -> int:
    raw = sys.stdin.read() if input_path == "-" else Path(input_path).read_text(encoding="utf-8")
    try:
        payload = loads_strict(raw)
    except ValueError as exc:
        raise ValueError(f"invalid JSON input: {exc}") from exc
    is_batch = isinstance(payload, list)
    items = payload if is_batch else [payload]

    prepared = []
    for i, item in enumerate(items):
        if not isinstance(item, dict) or "decision" not in item or "context" not in item:
            raise ValueError(f"item {i}: expected an object with 'decision' and 'context'")
        decision = item["decision"]
        if isinstance(decision, str):
            decision = {"decision": decision}
        if not isinstance(decision, dict):
            raise ValueError(f"item {i}: decision must be an object or a label")
        if not isinstance(item["context"], dict):
            raise ValueError(f"item {i}: context must be an object")
        prepared.append((decision, item["context"]))

    orch = AuditOrchestrator(config)
    results = []
    try:
        for decision, context in prepared:
            results.append(orch.audit_decision(decision, context))
    except Exception:
        if results:
            print(json.dumps(results, indent=2))
            print(f"error: stopped after {len(results)} of {len(prepared)} records; "
                  "those above are committed", file=sys.stderr)
        raise

    print(json.dumps(results if is_batch else results[0], indent=2))
    return 3 if any(r["status"] == "degraded" for r in results) else 0

def _blocking_chain_errors(orch: AuditOrchestrator) -> list[str]:
    valid, errors = orch.chain.verify_integrity()
    return [] if valid else errors

def _cmd_checkpoint(config: Config, check_path) -> int:
    from .checkpoint import build_checkpoint, load_checkpoint, verify_checkpoint
    orch = AuditOrchestrator(config)
    if check_path:
        valid, errors, warnings = verify_checkpoint(
            orch.chain, orch.signer, load_checkpoint(check_path))
        if valid:
            print("Checkpoint OK: the stored chain extends the checkpointed history.")
            for warning in warnings:
                print(f"  ! {warning}")
            return 0
        print("Checkpoint FAILED:")
        for err in errors:
            print(f"  - {err}")
        for warning in warnings:
            print(f"  ! {warning}")
        return 1
    blocking = _blocking_chain_errors(orch)
    if blocking:
        print("Refusing to checkpoint a chain that does not verify:", file=sys.stderr)
        for err in blocking:
            print(f"  - {err}", file=sys.stderr)
        return 1
    statement = build_checkpoint(orch.chain, orch.signer, clock=config.clock)
    print(json.dumps(statement, indent=2))
    return 0

def _cmd_check(config: Config, as_json: bool, strict: bool = False,
               stream: bool = False) -> int:
    chain_file = Path(config.resolved_chain_path())
    if stream and chain_file.exists():
        from .aggregate import aggregate_policy_for
        integrity, summary = _portfolio_from_stream(config, chain_file)
        result = aggregate_policy_for(config.aggregate_profile,
                                      config.aggregate_config_path).evaluate(summary)
        result["chain_valid"] = integrity["valid"]
        if not integrity["valid"]:
            result["passed"] = False
            result["chain_errors"] = integrity["errors"]
    else:
        result = AuditOrchestrator(config).check_aggregate_policy()

    if as_json:
        print(json.dumps(result, indent=2))
    else:
        status = "PASS" if result["passed"] else "BREACHED"
        print(f"Portfolio policy: {status} ({result['rules']} rules)")
        if not result.get("chain_valid", True):
            print("  - the stored chain does not verify, so these thresholds "
                  "describe a log nobody can vouch for:")
            for err in result.get("chain_errors", []):
                print(f"      {err}")
        for breach in result["breaches"]:
            print(f"  - [{breach['severity']}] {breach['id']}: {breach['detail']}")
        for skipped in result["not_evaluated"]:
            print(f"  ? {skipped['id']}: {skipped['detail']}")
    if not result["passed"]:
        return 1
    return EXIT_INCOMPLETE if strict and not result["complete"] else 0

def _cmd_prove(config: Config, index, since, head: bool, out_path) -> int:
    from .proofs import (
        build_consistency_proof,
        build_inclusion_proof,
        build_tree_head,
        load_proof,
    )
    orch = AuditOrchestrator(config)
    blocking = _blocking_chain_errors(orch)
    if blocking:
        print("Refusing to build a proof from a chain that does not verify:",
              file=sys.stderr)
        for err in blocking:
            print(f"  - {err}", file=sys.stderr)
        return 1
    if head:
        proof = build_tree_head(orch.chain, orch.signer, clock=config.clock)
    elif since is not None:
        earlier = load_proof(since)
        proof = build_consistency_proof(orch.chain, orch.signer, earlier,
                                        clock=config.clock)
    else:
        proof = build_inclusion_proof(orch.chain, orch.signer, index,
                                      clock=config.clock)

    rendered = json.dumps(proof, indent=2)
    if out_path:
        Path(out_path).write_text(rendered + "\n", encoding="utf-8")
        print(f"Proof written to {out_path}")
    else:
        print(rendered)
    return 0

def _cmd_verify_proof(config: Config, proof_path: str) -> int:
    from .crypto import make_signer
    from .proofs import load_proof, scheme_of, verify_proof

    proof = load_proof(proof_path)
    scheme = scheme_of(proof) or config.signature_scheme
    signer = make_signer(
        scheme,
        key_path=config.resolved_key_path(scheme),
        public_key_path=config.resolved_public_key_path(scheme))

    valid, errors = verify_proof(signer, proof)
    if valid:
        print(f"Proof OK ({proof.get('type')}).")
        if proof.get("type") == "inclusion_proof":
            head = proof["tree_head"]
            print(f"  record {proof['leaf_index']} of {head['tree_size']} "
                  f"is in the log rooted at {head['root_hash'][:16]}...")
        elif proof.get("type") == "consistency_proof":
            old, new = proof["old_tree_head"], proof["new_tree_head"]
            print(f"  the log grew from {old['tree_size']} to {new['tree_size']} "
                  "records with the earlier ones unchanged")
        return 0
    print(f"Proof FAILED ({proof.get('type')}):")
    for err in errors:
        print(f"  - {err}")
    return 1

def _cmd_reset(config: Config, assume_yes: bool = False) -> int:
    removed = []
    chain_path = Path(config.resolved_chain_path())
    if not assume_yes and sys.stdin.isatty() and chain_path.exists():
        answer = input(f"Delete the audit chain and keys in {config.state_dir}? [y/N] ")
        if answer.strip().lower() not in ("y", "yes"):
            print("Left untouched.")
            return 0
    candidates = [chain_path, lock_path_for(chain_path),
                  Path(config.resolved_drift_state_path())]
    schemes = ("ed25519", "hmac")
    if not config.key_path:
        candidates += [Path(config.resolved_key_path(s)) for s in schemes]
    if not config.public_key_path:
        public_paths = (config.resolved_public_key_path(s) for s in schemes)
        candidates += [Path(p) for p in public_paths if p]
    for path in candidates:
        if path.exists():
            path.unlink()
            removed.append(str(path))
    state_dir = Path(config.state_dir)
    if state_dir.is_dir():
        with contextlib.suppress(OSError):
            state_dir.rmdir()
    if removed:
        print("Removed: " + ", ".join(removed))
    else:
        print("No audit state to remove.")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
