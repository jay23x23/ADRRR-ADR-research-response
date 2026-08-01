import json
import tempfile
import unittest
from pathlib import Path

try:
    import yaml  # noqa: F401
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

from app import write_sigma_json


@unittest.skipUnless(HAS_YAML, "PyYAML is optional until Sigma export is used")
class SigmaExportTests(unittest.TestCase):
    def test_yaml_date_is_serialized_to_json_text(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            rule = root / "rule.yml"
            rule.write_text("""title: Test Rule
id: 11111111-1111-1111-1111-111111111111
date: 2026-07-31
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: example.exe
  condition: selection
""", encoding="utf-8")
            output = root / "rules.json"
            self.assertEqual(write_sigma_json(root, output), 1)
            value = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(value[0]["date"], "2026-07-31")

    def test_empty_export_is_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaises(RuntimeError): write_sigma_json(Path(folder), Path(folder) / "rules.json")


if __name__ == "__main__":
    unittest.main()
