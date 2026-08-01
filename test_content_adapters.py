import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from content_adapters import import_content


class ContentAdapterTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(__file__).resolve().parent
        self.samples = self.root / "fake_logs"

    def test_native_alert_adapters(self):
        for source, name in (("suricata", "sample-suricata-eve.jsonl"),
                             ("wazuh", "sample-wazuh-alerts.jsonl"),
                             ("yara", "sample-yara-results.jsonl")):
            with self.subTest(source=source):
                result = import_content(self.samples / name, source)
                self.assertEqual(result.mode, "native_alert_ingestion" if source != "yara" else "scan_result_ingestion")
                self.assertEqual(result.imported, 1)
                self.assertEqual(len(result.external_alerts), 1)

    def test_mitre_is_enrichment_not_detection(self):
        result = import_content(self.samples / "sample-mitre-stix.json", "mitre_attack")
        self.assertEqual(result.mode, "enrichment_only")
        self.assertEqual(result.executable, 0)
        self.assertEqual(len(result.enrichment), 1)

    def test_elastic_is_research_only(self):
        result = import_content(self.samples / "sample-elastic-rule.toml", "elastic")
        self.assertEqual(result.mode, "research_only")
        self.assertEqual(result.executable, 0)
        self.assertEqual(result.catalogue[0]["query_language"], "eql")

    def test_sentinel_and_splunk_are_research_only(self):
        for source, name, language in (("sentinel", "sample-sentinel-rule.json", "KQL"),
                                       ("splunk", "sample-splunk-detection.json", "SPL")):
            with self.subTest(source=source):
                result = import_content(self.samples / name, source)
                self.assertEqual(result.mode, "research_only")
                self.assertEqual(result.executable, 0)
                self.assertEqual(result.catalogue[0]["query_language"], language)

    def test_malformed_input_isolated_as_exception(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "broken.jsonl"
            path.write_text("{not-json}\n", encoding="utf-8")
            with self.assertRaises(json.JSONDecodeError):
                import_content(path, "suricata")

    def test_encrypted_or_unsafe_archives_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "empty.zip"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("README.txt", "no supported content")
            result = import_content(path, "elastic")
            self.assertEqual(result.imported, 0)


if __name__ == "__main__":
    unittest.main()
