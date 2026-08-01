import unittest

from vendor_connectors import VendorAlert, match_alert, techniques, tokens


class ConnectorTests(unittest.TestCase):
    def test_attack_technique_extraction(self):
        self.assertEqual(techniques({"technique": "T1059.001", "other": "T1003"}), ("T1003", "T1059.001"))

    def test_token_normalization(self):
        self.assertIn("powershell", tokens("Suspicious PowerShell Detection"))
        self.assertNotIn("suspicious", tokens("Suspicious PowerShell Detection"))

    def test_candidate_match_preserves_solution_codes(self):
        alert = VendorAlert(
            timestamp="2026-07-31T00:00:00+00:00", source="training", vendor_alert_id="A1",
            title="PowerShell command execution", description="Interpreter execution T1059.001",
            severity="high", status="new", host="ws01", user="jose", mitre_attack=("T1059.001",), raw={},
        )
        catalog = [{
            "alert_rule_id": "SIGMA-EXAMPLE", "title": "PowerShell Script Execution",
            "description": "Detects PowerShell", "tags": ["attack.t1059.001"],
            "solution_codes": [f"SIGMA-EXAMPLE-WINDOWS_11-S{index:02d}" for index in range(1, 6)],
        }]
        matches = match_alert(alert, catalog)
        self.assertEqual(matches[0]["alert_rule_id"], "SIGMA-EXAMPLE")
        self.assertGreaterEqual(matches[0]["score"], 0.7)
        self.assertEqual(len(matches[0]["solution_codes"]), 5)

    def test_unrelated_alert_does_not_force_match(self):
        alert = VendorAlert("2026-07-31T00:00:00+00:00", "training", "A2", "Disk temperature", "hardware", "low", "new", "ws01", "unknown", (), {})
        catalog = [{"alert_rule_id": "SIGMA-X", "title": "Kerberos ticket abuse", "description": "identity", "tags": [], "solution_codes": []}]
        self.assertEqual(match_alert(alert, catalog), [])


if __name__ == "__main__":
    unittest.main()
