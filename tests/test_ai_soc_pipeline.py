import json
import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from ai_soc_pipeline import run_pipeline, validate

class TestPipeline(unittest.TestCase):
    def setUp(self):
        path = Path(__file__).resolve().parents[1] / "evidence/ai-soc-2026-041/alerts.json"
        self.events = json.loads(path.read_text())

    def test_correlates_suspicious_principal(self):
        result = run_pipeline(self.events)
        self.assertEqual(len(result["findings"]), 1)
        self.assertEqual(result["findings"][0]["principal"], "svc-payments")
        self.assertEqual(result["findings"][0]["severity"], "high")

    def test_benign_principal_not_flagged(self):
        result = run_pipeline(self.events)
        self.assertNotIn("finance-reader", [f["principal"] for f in result["findings"]])

    def test_no_automated_response(self):
        result = run_pipeline(self.events)
        self.assertTrue(all(a["approval_required"] and a["status"] == "PENDING_HUMAN_REVIEW"
                            for a in result["proposed_actions"]))

    def test_duplicate_id_rejected(self):
        with self.assertRaises(ValueError):
            validate(self.events + [dict(self.events[0])])

    def test_evidence_ids_resolve(self):
        result = run_pipeline(self.events)
        ids = {e["id"] for e in self.events}
        self.assertTrue(all(set(f["evidence_ids"]) <= ids for f in result["findings"]))

if __name__ == "__main__":
    unittest.main()
