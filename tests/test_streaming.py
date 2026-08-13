import json
import tempfile
import unittest
from pathlib import Path

from decision_audit.chain import HashChain
from decision_audit.crypto import HmacSigner
from decision_audit.merkle import MerkleTree, leaf_hash
from decision_audit.streaming import StreamingMerkleRoot, verify_stream


class StreamingRootTests(unittest.TestCase):
    def test_matches_the_in_memory_tree_at_every_size(self):
        for n in range(0, 40):
            leaves = [leaf_hash(f"{i:064x}") for i in range(n)]
            incremental = StreamingMerkleRoot()
            for leaf in leaves:
                incremental.add(leaf)
            with self.subTest(n=n):
                self.assertEqual(incremental.root(), MerkleTree(leaves).root())


class VerifyStreamTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.state = Path(self._tmp.name)
        self.key_path = self.state / "hmac_key.bin"
        self.chain_path = self.state / "chain.jsonl"

    def _signer(self):
        return HmacSigner(str(self.key_path))

    def _chain(self):
        return HashChain(self._signer(), storage_path=str(self.chain_path))

    def _seed(self, count=9):
        chain = self._chain()
        for i in range(count):
            chain.add_record({"n": i, "anomaly": i % 4 == 0,
                              "status": "degraded" if i == 3 else "ok"})
        return chain

    def _both(self, full=False):
        streamed = verify_stream(self.chain_path, self._signer(), full=full)
        chain = self._chain()
        valid, errors = chain.verify_integrity(full=full)
        return streamed, {"valid": valid, "errors": errors,
                          "blocks": len(chain.chain),
                          "warnings": chain.warnings,
                          "root_hash": chain.tree_head()[1]}

    def test_agrees_on_a_file_with_no_header(self):
        self._seed()
        lines = self.chain_path.read_text().splitlines()
        self.chain_path.write_text("\n".join(lines[1:]) + "\n")

        streamed, loaded = self._both()
        self.assertFalse(streamed["valid"])
        self.assertEqual(streamed["errors"], loaded["errors"])
        self.assertEqual(streamed["blocks"], loaded["blocks"])
        self.assertIn("missing header line", streamed["errors"][0])

    def test_a_scheme_the_signer_does_not_match_is_reported(self):
        self._seed()
        lines = self.chain_path.read_text().splitlines()
        header = json.loads(lines[0])
        header["scheme"] = "ed25519"
        lines[0] = json.dumps(header, sort_keys=True, separators=(",", ":"))
        self.chain_path.write_text("\n".join(lines) + "\n")

        streamed = verify_stream(self.chain_path, self._signer())
        self.assertFalse(streamed["valid"])
        self.assertTrue(any("signed with 'ed25519'" in e for e in streamed["errors"]),
                        streamed["errors"])

    def test_agrees_on_a_stray_header_line(self):
        self._seed(4)
        lines = self.chain_path.read_text().splitlines()
        for position in (2, len(lines)):
            with self.subTest(position=position):
                spliced = [*lines[:position], lines[0], *lines[position:]]
                self.chain_path.write_text("\n".join(spliced) + "\n")
                streamed, loaded = self._both()
                self.assertFalse(streamed["valid"])
                self.assertEqual(streamed["errors"], loaded["errors"])
                self.assertIn("a second header line", streamed["errors"][0])

    def test_agrees_word_for_word_on_an_unreadable_file(self):
        self._seed(4)
        good = self.chain_path.read_text()
        for label, contents in (
            ("record missing a field", good + '{"index": 4}\n'),
            ("complete but unparseable", good + "{ not json }\n"),
            ("nothing recognisable", "total nonsense\n"),
        ):
            with self.subTest(case=label):
                self.chain_path.write_text(contents)
                streamed, loaded = self._both()
                self.assertFalse(streamed["valid"])
                self.assertEqual(streamed["errors"], loaded["errors"])

    def test_agrees_on_the_order_of_the_errors_too(self):
        self._seed(5)
        lines = self.chain_path.read_text().splitlines()
        block = json.loads(lines[2])
        block["data"]["n"] = 999
        lines[2] = json.dumps(block, sort_keys=True, separators=(",", ":"))
        header = json.loads(lines[0])
        header["scheme"] = "ed25519"
        lines[0] = json.dumps(header, sort_keys=True, separators=(",", ":"))
        self.chain_path.write_text("\n".join(lines) + "\n")
        self.key_path.unlink()

        streamed, loaded = self._both()
        self.assertEqual(streamed["errors"], loaded["errors"])
        self.assertEqual(len(streamed["errors"]), 3, streamed["errors"])

    def test_agrees_on_the_order_within_one_block_too(self):
        self._seed(5)
        lines = self.chain_path.read_text().splitlines()
        for target in (2, len(lines) - 1):
            with self.subTest(block=target):
                broken = list(lines)
                block = json.loads(broken[target])
                block["data"]["n"] = 999
                block["prev_hash"] = "f" * 64
                block["signature"] = "00" * 32
                broken[target] = json.dumps(block, sort_keys=True,
                                            separators=(",", ":"))
                self.chain_path.write_text("\n".join(broken) + "\n")
                for full in (False, True):
                    streamed, loaded = self._both(full=full)
                    self.assertEqual(streamed["errors"], loaded["errors"])

    def test_a_partial_tally_is_not_handed_back_as_the_summary(self):
        from decision_audit.portfolio import PortfolioAccumulator

        self._seed(9)
        lines = self.chain_path.read_text().splitlines()
        lines[6] = "{ not a record }"
        self.chain_path.write_text("\n".join(lines) + "\n")

        accumulator = PortfolioAccumulator(min_group_size=1)
        streamed = verify_stream(self.chain_path, self._signer(), summary=accumulator)
        self.assertFalse(streamed["valid"])
        self.assertEqual(streamed["blocks"], 0)
        self.assertEqual(accumulator.result()["audits"], 0)

    def test_no_root_is_reported_for_a_file_that_could_not_be_read(self):
        self._seed(3)
        self.chain_path.write_text("total nonsense\n")
        self.assertTrue(self._chain().unreadable)
        self.assertIsNone(verify_stream(self.chain_path, self._signer())["root_hash"])

    def test_agrees_with_the_in_memory_pass_on_a_good_chain(self):
        self._seed()
        streamed, loaded = self._both()
        self.assertTrue(streamed["valid"])
        self.assertEqual(streamed["valid"], loaded["valid"])
        self.assertEqual(streamed["errors"], loaded["errors"])
        self.assertEqual(streamed["blocks"], loaded["blocks"])
        self.assertEqual(streamed["root_hash"], loaded["root_hash"])

    def test_counts_match_the_records(self):
        self._seed(9)
        streamed = verify_stream(self.chain_path, self._signer())
        self.assertEqual(streamed["blocks"], 9)
        self.assertEqual(streamed["anomalies"], 3)
        self.assertEqual(streamed["degraded_records"], 1)

    def test_agrees_on_a_tampered_record(self):
        self._seed()
        lines = self.chain_path.read_text().splitlines()
        block = json.loads(lines[3])
        block["data"]["n"] = 999
        lines[3] = json.dumps(block, sort_keys=True, separators=(",", ":"))
        self.chain_path.write_text("\n".join(lines) + "\n")

        streamed, loaded = self._both()
        self.assertFalse(streamed["valid"])
        self.assertEqual(streamed["errors"], loaded["errors"])

    def test_agrees_on_a_broken_link(self):
        self._seed()
        lines = self.chain_path.read_text().splitlines()
        block = json.loads(lines[4])
        block["prev_hash"] = "ab" * 32
        lines[4] = json.dumps(block, sort_keys=True, separators=(",", ":"))
        self.chain_path.write_text("\n".join(lines) + "\n")

        streamed, loaded = self._both()
        self.assertFalse(streamed["valid"])
        self.assertEqual(streamed["errors"], loaded["errors"])

    def test_full_mode_checks_every_signature(self):
        self._seed()
        lines = self.chain_path.read_text().splitlines()
        block = json.loads(lines[2])
        block["signature"] = "00" * 32
        lines[2] = json.dumps(block, sort_keys=True, separators=(",", ":"))
        self.chain_path.write_text("\n".join(lines) + "\n")

        self.assertTrue(verify_stream(self.chain_path, self._signer())["valid"])
        full = verify_stream(self.chain_path, self._signer(), full=True)
        self.assertFalse(full["valid"])
        self.assertEqual(full["errors"], ["block 1: invalid signature"])

    def test_forged_head_signature_is_caught_in_the_default_pass(self):
        self._seed()
        lines = self.chain_path.read_text().splitlines()
        block = json.loads(lines[-1])
        block["signature"] = "00" * 32
        lines[-1] = json.dumps(block, sort_keys=True, separators=(",", ":"))
        self.chain_path.write_text("\n".join(lines) + "\n")

        self.assertFalse(verify_stream(self.chain_path, self._signer())["valid"])

    def test_torn_final_record_is_skipped_as_it_is_on_load(self):
        self._seed(4)
        raw = self.chain_path.read_bytes()
        self.chain_path.write_bytes(raw[:-20])

        streamed, loaded = self._both()
        self.assertEqual(streamed["blocks"], 3)
        self.assertEqual(streamed["blocks"], loaded["blocks"])
        self.assertTrue(streamed["valid"])
        self.assertEqual(streamed["warnings"], loaded["warnings"])
        self.assertTrue(any("cut short" in w for w in streamed["warnings"]),
                        streamed["warnings"])

    def test_the_summary_matches_the_one_built_from_a_loaded_chain(self):
        from decision_audit.portfolio import PortfolioAccumulator

        chain = self._seed(12)
        accumulator = PortfolioAccumulator(min_group_size=4)
        streamed = verify_stream(self.chain_path, self._signer(), summary=accumulator)
        self.assertTrue(streamed["valid"], streamed["errors"])

        loaded = PortfolioAccumulator(min_group_size=4)
        loaded.extend(node.data for node in chain.chain)
        self.assertEqual(accumulator.result(), loaded.result())
        self.assertEqual(accumulator.result()["audits"], 12)

    def test_corrupt_file_is_reported_not_raised(self):
        self._seed(2)
        self.chain_path.write_text("total nonsense\n")
        result = verify_stream(self.chain_path, self._signer())
        self.assertFalse(result["valid"])
        self.assertTrue(any("unreadable" in e for e in result["errors"]))

    def test_memory_does_not_grow_with_the_log(self):
        import tracemalloc

        self._seed(2000)
        lines = self.chain_path.read_text(encoding="utf-8").splitlines(keepends=True)
        header, records = lines[0], lines[1:]

        def peak_over(count):
            prefix = self.state / f"prefix_{count}.jsonl"
            prefix.write_text(header + "".join(records[:count]), encoding="utf-8")
            peaks = []
            for _ in range(5):
                tracemalloc.start()
                result = verify_stream(prefix, self._signer())
                _, peak = tracemalloc.get_traced_memory()
                tracemalloc.stop()
                self.assertTrue(result["valid"], result["errors"])
                self.assertEqual(result["blocks"], count)
                peaks.append(peak)
            return min(peaks)

        small = peak_over(125)
        large = peak_over(2000)
        self.assertLess(large, small * 1.5,
                        f"peak grew from {small} to {large} bytes over a log "
                        "sixteen times longer")


if __name__ == "__main__":
    unittest.main()
