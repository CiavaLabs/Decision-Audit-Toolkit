import json
import tempfile
import unittest
from pathlib import Path

from decision_audit.chain import (
    GENESIS_HASH,
    ChainIntegrityError,
    HashChain,
    detect_chain_scheme,
)
from decision_audit.crypto import Ed25519Signer, HmacSigner


def read_blocks(chain_path: Path):
    lines = [json.loads(line) for line in chain_path.read_text().splitlines() if line.strip()]
    return lines[0], lines[1:]


def write_blocks(chain_path: Path, header, blocks):
    lines = [json.dumps(header)] + [json.dumps(block) for block in blocks]
    chain_path.write_text("\n".join(lines) + "\n")


class HashChainTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.state = Path(self._tmp.name)
        self.key_path = self.state / "hmac_key.bin"
        self.chain_path = self.state / "chain.jsonl"

    def _chain(self) -> HashChain:
        return HashChain(HmacSigner(str(self.key_path)), storage_path=str(self.chain_path))

    def test_append_verify_and_reload(self):
        chain = self._chain()
        for i in range(3):
            chain.add_record({"n": i})
        valid, errors = chain.verify_integrity()
        self.assertTrue(valid, errors)

        reloaded = self._chain()
        valid, errors = reloaded.verify_integrity()
        self.assertTrue(valid, errors)
        self.assertEqual([node.data["n"] for node in reloaded.chain], [0, 1, 2])

    def test_storage_is_one_line_per_block(self):
        chain = self._chain()
        for i in range(3):
            chain.add_record({"n": i})
        header, blocks = read_blocks(self.chain_path)
        self.assertEqual(header["type"], "header")
        self.assertEqual(header["scheme"], "hmac")
        self.assertEqual(len(blocks), 3)

    def test_in_memory_chain(self):
        chain = HashChain(HmacSigner())
        chain.add_record({"a": 1})
        self.assertTrue(chain.verify_integrity()[0])

    def test_empty_chain_file_still_gets_a_header(self):
        self.chain_path.touch()
        chain = self._chain()
        chain.add_record({"n": 0})
        chain.add_record({"n": 1})

        header, blocks = read_blocks(self.chain_path)
        self.assertEqual(header["type"], "header")
        self.assertEqual(len(blocks), 2)
        reloaded = self._chain()
        self.assertTrue(reloaded.verify_integrity()[0])
        self.assertEqual(len(reloaded.chain), 2)

    def test_wrong_scheme_reports_and_refuses_to_append(self):
        chain = self._chain()
        chain.add_record({"n": 0})

        other = HashChain(Ed25519Signer(str(self.state / "ed.bin"), str(self.state / "ed.pub")),
                          storage_path=str(self.chain_path))
        valid, errors = other.verify_integrity()
        self.assertFalse(valid)
        self.assertTrue(any("configured scheme" in e for e in errors), errors)
        with self.assertRaises(ChainIntegrityError):
            other.add_record({"n": 1})
        self.assertTrue(self._chain().verify_integrity()[0])

    def test_block_index_must_match_position(self):
        chain = self._chain()
        for i in range(3):
            chain.add_record({"n": i})
        header, blocks = read_blocks(self.chain_path)
        blocks[1]["index"] = 7
        write_blocks(self.chain_path, header, blocks)

        valid, errors = self._chain().verify_integrity()
        self.assertFalse(valid)
        self.assertTrue(any("index recorded as 7" in e for e in errors), errors)

    def test_second_writer_is_picked_up_before_appending(self):
        first = self._chain()
        second = self._chain()
        first.add_record({"who": "first"})
        second.add_record({"who": "second"})

        reloaded = self._chain()
        valid, errors = reloaded.verify_integrity()
        self.assertTrue(valid, errors)
        self.assertEqual([node.data["who"] for node in reloaded.chain], ["first", "second"])
        self.assertEqual([node.index for node in reloaded.chain], [0, 1])

    def test_record_factory_sees_the_settled_index(self):
        first = self._chain()
        second = self._chain()
        first.add_record({"n": 0})
        second.add_record(lambda index: {"stamped": index})
        self.assertEqual(second.chain[-1].data["stamped"], 1)

    def test_non_finite_values_are_refused(self):
        chain = self._chain()
        with self.assertRaises(ValueError):
            chain.add_record({"score": float("inf")})

    def test_partial_trailing_line_is_left_for_its_writer(self):
        first = self._chain()
        first.add_record({"n": 0})
        second = self._chain()
        first.add_record({"n": 1})
        with open(self.chain_path, "a", encoding="utf-8") as fh:
            fh.write('{"index":2,"timesta')

        second._sync_from_disk_locked()
        self.assertEqual(len(second.chain), 2)
        self.assertLess(second._read_offset, self.chain_path.stat().st_size)

    def test_blocks_from_another_writer_must_hash_to_their_content(self):
        first = self._chain()
        first.add_record({"n": 0})
        second = self._chain()

        head = first.chain[-1]
        forged = {
            "index": 1,
            "timestamp": 1000.0,
            "data": {"n": 99},
            "prev_hash": head.hash,
            "hash": first._compute_hash(1, 1000.0, {"n": 1}, head.hash),
            "signature": "00" * 64,
        }
        with open(self.chain_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(forged, sort_keys=True, separators=(",", ":")) + "\n")

        second._sync_from_disk_locked()
        self.assertFalse(second._append_allowed)
        with self.assertRaises(ChainIntegrityError):
            second.add_record({"n": 2})

    def test_tampered_data_is_detected_and_appends_refused(self):
        chain = self._chain()
        for i in range(3):
            chain.add_record({"n": i})

        header, blocks = read_blocks(self.chain_path)
        blocks[1]["data"]["n"] = 999
        write_blocks(self.chain_path, header, blocks)

        tampered = self._chain()
        valid, errors = tampered.verify_integrity()
        self.assertFalse(valid)
        self.assertTrue(any("hash mismatch" in e for e in errors), errors)
        with self.assertRaises(ChainIntegrityError):
            tampered.add_record({"n": 3})

    def test_broken_link_is_detected(self):
        chain = self._chain()
        for i in range(3):
            chain.add_record({"n": i})
        header, blocks = read_blocks(self.chain_path)
        blocks[2]["prev_hash"] = "ab" * 32
        write_blocks(self.chain_path, header, blocks)

        valid, errors = self._chain().verify_integrity()
        self.assertFalse(valid)
        self.assertTrue(any("broken link" in e for e in errors), errors)

    def test_corrupt_file_is_reported_not_raised(self):
        chain = self._chain()
        chain.add_record({"n": 0})
        self.chain_path.write_text("not json {{\nalso not json\n")

        corrupt = self._chain()
        valid, errors = corrupt.verify_integrity()
        self.assertFalse(valid)
        self.assertTrue(any("unreadable chain file" in e for e in errors), errors)
        with self.assertRaises(ChainIntegrityError):
            corrupt.add_record({"n": 1})

    def test_torn_final_record_is_dropped_and_the_log_survives(self):
        chain = self._chain()
        for i in range(3):
            chain.add_record({"n": i})
        raw = self.chain_path.read_text()
        self.chain_path.write_text(raw[:-40])

        recovered = self._chain()
        valid, errors = recovered.verify_integrity()
        self.assertTrue(valid, errors)
        self.assertEqual([n.data["n"] for n in recovered.chain], [0, 1])
        self.assertTrue(any("cut short" in w for w in recovered.warnings),
                        recovered.warnings)

        recovered.add_record({"n": 3})
        reloaded = self._chain()
        self.assertTrue(reloaded.verify_integrity()[0])
        self.assertEqual([n.data["n"] for n in reloaded.chain], [0, 1, 3])

    def test_record_that_lost_only_its_newline_does_not_splice(self):
        chain = self._chain()
        for i in range(2):
            chain.add_record({"n": i})
        raw = self.chain_path.read_bytes()
        self.chain_path.write_bytes(raw[:-1])

        recovered = self._chain()
        self.assertEqual([n.data["n"] for n in recovered.chain], [0])
        recovered.add_record({"n": 2})

        reloaded = self._chain()
        valid, errors = reloaded.verify_integrity()
        self.assertTrue(valid, errors)
        self.assertEqual([n.data["n"] for n in reloaded.chain], [0, 2])

    def test_complete_but_corrupt_record_still_fails_hard(self):
        chain = self._chain()
        chain.add_record({"n": 0})
        raw = self.chain_path.read_text()
        self.chain_path.write_text(raw + "{ not json at all }\n")

        corrupt = self._chain()
        valid, errors = corrupt.verify_integrity()
        self.assertFalse(valid)
        self.assertTrue(any("invalid JSON" in e for e in errors), errors)
        with self.assertRaises(ChainIntegrityError):
            corrupt.add_record({"n": 1})

    def _rehash_cascade(self, chain, blocks, start):
        for i in range(start, len(blocks)):
            if i:
                blocks[i]["prev_hash"] = blocks[i - 1]["hash"]
            blocks[i]["hash"] = chain._compute_hash(
                blocks[i]["index"], blocks[i]["timestamp"],
                blocks[i]["data"], blocks[i]["prev_hash"])
        return blocks

    def test_a_field_of_the_wrong_type_is_reported_not_raised(self):
        broken = {
            "timestamp": "2026-01-01",
            "index": "0",
            "data": None,
            "prev_hash": 17,
            "hash": ["not", "a", "hash"],
            "signature": 12345,
        }
        for field, value in broken.items():
            with self.subTest(field=field):
                self.chain_path.unlink(missing_ok=True)
                chain = self._chain()
                chain.add_record({"n": 0})
                chain.add_record({"n": 1})
                header, blocks = read_blocks(self.chain_path)
                blocks[1][field] = value
                write_blocks(self.chain_path, header, blocks)

                reopened = self._chain()
                valid, errors = reopened.verify_integrity()
                self.assertFalse(valid)
                self.assertTrue(any("unreadable chain file" in e for e in errors), errors)

    def test_a_non_finite_timestamp_is_refused_on_load(self):
        chain = self._chain()
        chain.add_record({"n": 0})
        raw = self.chain_path.read_text()
        self.chain_path.write_text(raw.replace('"timestamp":', '"timestamp":NaN,"_t":', 1))

        valid, errors = self._chain().verify_integrity()
        self.assertFalse(valid)
        self.assertTrue(any("unreadable chain file" in e for e in errors), errors)

    def test_a_second_header_line_is_corruption(self):
        first = self._chain()
        first.add_record({"n": 0})
        second = self._chain()
        header = self.chain_path.read_text().splitlines()[0]
        with open(self.chain_path, "a", encoding="utf-8") as fh:
            fh.write(header + "\n")

        valid, errors = self._chain().verify_integrity()
        self.assertFalse(valid)
        self.assertTrue(any("a second header line" in e for e in errors), errors)
        with self.assertRaises(ChainIntegrityError):
            second.add_record({"n": 1})

    def test_a_writer_will_not_link_onto_a_file_with_no_header(self):
        waiting = self._chain()
        forged = {"index": 0, "timestamp": 1000.0, "data": {"n": 0},
                  "prev_hash": GENESIS_HASH, "signature": "00" * 32}
        forged["hash"] = waiting._compute_hash(
            forged["index"], forged["timestamp"], forged["data"], forged["prev_hash"])
        self.chain_path.write_text(
            json.dumps(forged, sort_keys=True, separators=(",", ":")) + "\n")

        with self.assertRaises(ChainIntegrityError):
            waiting.add_record({"n": 1})

    def test_a_failed_load_does_not_keep_the_offset_it_came_from(self):
        chain = self._chain()
        chain.add_record({"n": 0})
        self.chain_path.write_text("not json at all\n")
        reopened = self._chain()
        self.assertFalse(reopened.verify_integrity()[0])
        self.assertEqual(reopened._read_offset, 0)

    def test_edited_record_is_caught_even_with_the_hashes_recomputed(self):
        chain = self._chain()
        for i in range(5):
            chain.add_record({"amount": 100 * i})
        header, blocks = read_blocks(self.chain_path)
        blocks[2]["data"]["amount"] = 999999
        write_blocks(self.chain_path, header,
                     self._rehash_cascade(chain, blocks, 2))

        valid, errors = self._chain().verify_integrity()
        self.assertFalse(valid)
        self.assertEqual(errors, ["block 4: invalid signature"])

    def test_appending_is_refused_when_only_the_head_signature_is_wrong(self):
        chain = self._chain()
        for i in range(4):
            chain.add_record({"amount": 100 * i})
        header, blocks = read_blocks(self.chain_path)
        blocks[1]["data"]["amount"] = 999999
        write_blocks(self.chain_path, header, self._rehash_cascade(chain, blocks, 1))

        reopened = self._chain()
        with self.assertRaises(ChainIntegrityError):
            reopened.add_record({"amount": 0})
        self.assertEqual(len(read_blocks(self.chain_path)[1]), 4)

    def test_middle_signature_tampering_needs_the_full_pass(self):
        chain = self._chain()
        for i in range(4):
            chain.add_record({"n": i})
        header, blocks = read_blocks(self.chain_path)
        blocks[1]["signature"] = "ab" * 32
        write_blocks(self.chain_path, header, blocks)

        fast_valid, _ = self._chain().verify_integrity()
        self.assertTrue(fast_valid)

        full_valid, errors = self._chain().verify_integrity(full=True)
        self.assertFalse(full_valid)
        self.assertEqual(errors, ["block 1: invalid signature"])

    def test_default_verification_checks_one_signature_not_n(self):
        chain = self._chain()
        for i in range(6):
            chain.add_record({"n": i})

        reloaded = self._chain()
        calls = []
        real_verify = reloaded.signer.verify
        reloaded.signer.verify = lambda m, s: (calls.append(m), real_verify(m, s))[1]

        reloaded.verify_integrity()
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0], reloaded.chain[-1].hash.encode())

        calls.clear()
        reloaded.verify_integrity(full=True)
        self.assertEqual(len(calls), 6)

    def test_sync_refuses_a_concurrent_block_with_a_bad_signature(self):
        writer = self._chain()
        writer.add_record({"n": 0})

        other = self._chain()
        head = writer.chain[-1]
        forged = {
            "index": 1, "timestamp": head.timestamp + 1, "data": {"forged": True},
            "prev_hash": head.hash, "signature": "00" * 32,
        }
        forged["hash"] = writer._compute_hash(
            forged["index"], forged["timestamp"], forged["data"], forged["prev_hash"])
        with self.chain_path.open("a") as fh:
            fh.write(json.dumps(forged, sort_keys=True, separators=(",", ":")) + "\n")

        with self.assertRaises(ChainIntegrityError):
            other.add_record({"n": 1})

    def test_verify_rejects_timestamps_that_run_backwards(self):
        chain = self._chain()
        chain.add_record({"n": 0})
        chain.add_record({"n": 1})
        header, blocks = read_blocks(self.chain_path)
        blocks[1]["timestamp"] = blocks[0]["timestamp"] - 100
        blocks[1]["hash"] = chain._compute_hash(
            blocks[1]["index"], blocks[1]["timestamp"], blocks[1]["data"],
            blocks[1]["prev_hash"])
        blocks[1]["signature"] = HmacSigner(str(self.key_path)).sign(
            blocks[1]["hash"].encode()).hex()
        write_blocks(self.chain_path, header, blocks)

        valid, errors = self._chain().verify_integrity()
        self.assertFalse(valid)
        self.assertTrue(any("precedes" in e for e in errors), errors)

    def test_append_clamps_a_clock_that_steps_backwards(self):
        readings = iter([5000.0, 1000.0, 3000.0])
        chain = HashChain(HmacSigner(str(self.key_path)),
                          storage_path=str(self.chain_path),
                          clock=lambda: next(readings))
        for i in range(3):
            chain.add_record({"n": i})

        self.assertEqual([n.timestamp for n in chain.chain], [5000.0, 5000.0, 5000.0])
        self.assertEqual(chain.clock_regressions, 2)
        valid, errors = self._chain().verify_integrity()
        self.assertTrue(valid, errors)

    def test_missing_key_is_reported(self):
        chain = self._chain()
        chain.add_record({"n": 0})
        self.key_path.unlink()

        valid, errors = self._chain().verify_integrity()
        self.assertFalse(valid)
        self.assertTrue(any("verification key not found" in e for e in errors), errors)

    def test_read_only_construction_creates_no_state(self):
        self._chain().verify_integrity()
        self.assertFalse(self.chain_path.exists())
        self.assertFalse(self.key_path.exists())

    def test_detect_chain_scheme(self):
        self.assertIsNone(detect_chain_scheme(self.chain_path))
        self._chain().add_record({"n": 0})
        self.assertEqual(detect_chain_scheme(self.chain_path), "hmac")


if __name__ == "__main__":
    unittest.main()
