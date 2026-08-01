import json
import tempfile
import unittest
from pathlib import Path

from custom_rule_store import create, load
from declarative_engine import evaluate_detection, validate_detection


class DeclarativeEngineTests(unittest.TestCase):
    def test_boolean_and_modifiers(self):
        detection = {
            "selection": {"Image|endswith": "powershell.exe", "CommandLine|contains": "-enc"},
            "filter": {"ParentImage|endswith": "approved-agent.exe"},
            "condition": "selection and not filter",
        }
        validate_detection(detection)
        event = {"Image": "C:\\Windows\\powershell.exe", "CommandLine": "powershell -enc TEST", "ParentImage": "explorer.exe"}
        self.assertTrue(evaluate_detection(detection, event))

    def test_one_of_quantifier(self):
        detection = {"selection_a": {"EventID": 4625}, "selection_b": {"EventID": 4688}, "condition": "1 of selection_*"}
        self.assertTrue(evaluate_detection(detection, {"EventID": 4688}))

    def test_unsupported_aggregation_rejected(self):
        with self.assertRaises(ValueError):
            validate_detection({"selection": {"EventID": 4625}, "condition": "selection | count() by User > 5"})

    def test_custom_code_is_unique_and_five_responses_required(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "rules.json"
            payload = {"title": "Organization test alert", "environment": "ubuntu", "severity": "medium", "event_type": "process_creation", "detection": {"selection": {"process_name": "example"}, "condition": "selection"}, "responses": [f"Response {index}" for index in range(1, 6)]}
            first, second = create(path, payload), create(path, payload)
            self.assertEqual(first["alert_rule_id"], "USR-UBU-00001")
            self.assertEqual(second["alert_rule_id"], "USR-UBU-00002")
            self.assertEqual(len(load(path)), 2)


if __name__ == "__main__":
    unittest.main()
