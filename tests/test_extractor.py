"""
tests/test_extractor.py
────────────────────────
Basic unit tests for the core forensics engine.

Run with:
    python -m pytest tests/ -v
  or simply:
    python tests/test_extractor.py
"""

import sys
import os
import json
import hashlib
import tempfile
import unittest
from pathlib import Path

# ── Make sure project root is importable ──────────────────────
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.utils       import sha256_hash, safe_str, parse_pdf_date, days_between
from core.risk_scorer import compute_risk_score
from core.hash_ledger import (
    compute_merkle_root, register_document,
    load_ledger, verify_ledger_integrity, DEFAULT_LEDGER_PATH
)


# ══════════════════════════════════════════════════════════════
# TEST GROUP 1: Utility Functions
# ══════════════════════════════════════════════════════════════

class TestUtils(unittest.TestCase):

    def test_safe_str_none(self):
        """safe_str(None) should return 'N/A', not crash."""
        self.assertEqual(safe_str(None), "N/A")

    def test_safe_str_value(self):
        self.assertEqual(safe_str("  hello  "), "hello")

    def test_sha256_hash_consistency(self):
        """Same file must always produce the same hash."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pdf") as f:
            f.write(b"fake pdf content")
            path = f.name
        try:
            h1 = sha256_hash(path)
            h2 = sha256_hash(path)
            self.assertEqual(h1, h2)
            self.assertEqual(len(h1), 64)   # SHA-256 hex = 64 chars
        finally:
            os.unlink(path)

    def test_sha256_hash_changes_on_modification(self):
        """Different content must produce different hashes."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"original content")
            path = f.name
        try:
            h1 = sha256_hash(path)
            with open(path, "wb") as f:
                f.write(b"tampered content")
            h2 = sha256_hash(path)
            self.assertNotEqual(h1, h2, "Tampered file should have a different hash")
        finally:
            os.unlink(path)

    def test_parse_pdf_date_standard(self):
        """Standard PDF date string should parse correctly."""
        result = parse_pdf_date("D:20230615120000")
        self.assertIn("2023-06-15", result)

    def test_parse_pdf_date_na(self):
        self.assertEqual(parse_pdf_date(""), "N/A")
        self.assertEqual(parse_pdf_date(None), "N/A")

    def test_days_between(self):
        self.assertEqual(days_between("2023-01-01", "2023-01-11"), 10)
        self.assertEqual(days_between("2023-01-11", "2023-01-01"), 10)  # abs value

    def test_days_between_bad_input(self):
        self.assertIsNone(days_between("not-a-date", "2023-01-01"))


# ══════════════════════════════════════════════════════════════
# TEST GROUP 2: Risk Scorer
# ══════════════════════════════════════════════════════════════

class TestRiskScorer(unittest.TestCase):

    def _make_meta(self, flags):
        return {"forensic_flags": flags}

    def test_no_flags_clean(self):
        meta = self._make_meta([])
        result = compute_risk_score(meta)
        self.assertEqual(result["risk_score"], 0)
        self.assertEqual(result["risk_level"], "CLEAN")

    def test_one_high_flag(self):
        meta = self._make_meta([{"severity": "HIGH", "code": "TEST", "detail": "x"}])
        result = compute_risk_score(meta)
        self.assertEqual(result["risk_score"], 40)
        self.assertEqual(result["risk_level"], "HIGH")

    def test_two_high_flags_critical(self):
        flags = [
            {"severity": "HIGH",   "code": "F1", "detail": "a"},
            {"severity": "HIGH",   "code": "F2", "detail": "b"},
        ]
        result = compute_risk_score(self._make_meta(flags))
        self.assertEqual(result["risk_score"], 80)   # 40+40 = 80, capped at 100
        self.assertEqual(result["risk_level"], "CRITICAL")

    def test_score_capped_at_100(self):
        flags = [{"severity": "HIGH", "code": f"F{i}", "detail": "x"} for i in range(10)]
        result = compute_risk_score(self._make_meta(flags))
        self.assertLessEqual(result["risk_score"], 100)

    def test_medium_flag_score(self):
        meta = self._make_meta([{"severity": "MEDIUM", "code": "T", "detail": "x"}])
        result = compute_risk_score(meta)
        self.assertEqual(result["risk_score"], 20)
        self.assertEqual(result["risk_level"], "MEDIUM")

    def test_flag_counts(self):
        flags = [
            {"severity": "HIGH",   "code": "H", "detail": ""},
            {"severity": "MEDIUM", "code": "M", "detail": ""},
            {"severity": "LOW",    "code": "L", "detail": ""},
        ]
        result = compute_risk_score(self._make_meta(flags))
        self.assertEqual(result["high_flags"],   1)
        self.assertEqual(result["medium_flags"],  1)
        self.assertEqual(result["low_flags"],     1)
        self.assertEqual(result["flags_count"],   3)


# ══════════════════════════════════════════════════════════════
# TEST GROUP 3: Merkle Tree
# ══════════════════════════════════════════════════════════════

class TestMerkleTree(unittest.TestCase):

    def test_single_hash(self):
        h = "a" * 64
        self.assertEqual(compute_merkle_root([h]), h)

    def test_empty(self):
        self.assertIsNone(compute_merkle_root([]))

    def test_two_hashes_deterministic(self):
        h1 = hashlib.sha256(b"doc1").hexdigest()
        h2 = hashlib.sha256(b"doc2").hexdigest()
        root1 = compute_merkle_root([h1, h2])
        root2 = compute_merkle_root([h1, h2])
        self.assertEqual(root1, root2)

    def test_different_order_gives_different_root(self):
        h1 = hashlib.sha256(b"doc1").hexdigest()
        h2 = hashlib.sha256(b"doc2").hexdigest()
        root_ab = compute_merkle_root([h1, h2])
        root_ba = compute_merkle_root([h2, h1])
        self.assertNotEqual(root_ab, root_ba)

    def test_tamper_changes_root(self):
        h1 = hashlib.sha256(b"salary_slip.pdf").hexdigest()
        h2 = hashlib.sha256(b"land_record.pdf").hexdigest()
        original_root = compute_merkle_root([h1, h2])
        tampered_h2   = hashlib.sha256(b"land_record_tampered.pdf").hexdigest()
        tampered_root = compute_merkle_root([h1, tampered_h2])
        self.assertNotEqual(original_root, tampered_root)


# ══════════════════════════════════════════════════════════════
# TEST GROUP 4: Hash Ledger (uses temp ledger file)
# ══════════════════════════════════════════════════════════════

class TestHashLedger(unittest.TestCase):

    def setUp(self):
        """Use a temporary ledger file so we don't corrupt the real one."""
        self.tmp_ledger = Path(tempfile.mktemp(suffix="_ledger.json"))

    def tearDown(self):
        if self.tmp_ledger.exists():
            self.tmp_ledger.unlink()

    def _make_temp_file(self, content: bytes) -> str:
        f = tempfile.NamedTemporaryFile(delete=False, suffix=".pdf")
        f.write(content)
        f.close()
        return f.name

    def test_first_registration(self):
        path = self._make_temp_file(b"salary slip content")
        try:
            h = sha256_hash(path)
            result = register_document(path, h, ledger_path=self.tmp_ledger)
            self.assertEqual(result["status"], "REGISTERED")
        finally:
            os.unlink(path)

    def test_duplicate_same_hash(self):
        path = self._make_temp_file(b"same content")
        try:
            h = sha256_hash(path)
            register_document(path, h, ledger_path=self.tmp_ledger)
            result = register_document(path, h, ledger_path=self.tmp_ledger)
            self.assertEqual(result["status"], "DUPLICATE_SUBMISSION")
        finally:
            os.unlink(path)

    def test_hash_mismatch_detection(self):
        """Simulates: document re-submitted with different content (tampered)."""
        path = self._make_temp_file(b"original salary 30000")
        try:
            original_hash = sha256_hash(path)
            register_document(path, original_hash, ledger_path=self.tmp_ledger)

            # Tamper: now the document has different content → different hash
            tampered_hash = hashlib.sha256(b"tampered salary 60000").hexdigest()
            result = register_document(path, tampered_hash, ledger_path=self.tmp_ledger)
            self.assertEqual(result["status"], "HASH_MISMATCH")
            self.assertEqual(result["severity"], "CRITICAL")
        finally:
            os.unlink(path)

    def test_ledger_integrity_check(self):
        path = self._make_temp_file(b"test doc")
        try:
            h = sha256_hash(path)
            register_document(path, h, ledger_path=self.tmp_ledger)
            integrity = verify_ledger_integrity(ledger_path=self.tmp_ledger)
            self.assertTrue(integrity["intact"])
        finally:
            os.unlink(path)


# ══════════════════════════════════════════════════════════════
# RUNNER
# ══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    unittest.main(verbosity=2)
