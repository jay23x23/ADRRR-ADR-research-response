import json
import tempfile
import unittest
from pathlib import Path

from declarative_engine import validate_detection
from security_controls import append_audit, public_error, redact, validate_https_url


class SecurityControlTests(unittest.TestCase):
    def test_recursive_secret_redaction(self):
        value = redact({"user": "jose", "Authorization": "Bearer secret", "nested": {"api_token": "value"}})
        self.assertEqual(value["Authorization"], "[REDACTED]")
        self.assertEqual(value["nested"]["api_token"], "[REDACTED]")
        self.assertEqual(value["user"], "jose")

    def test_connector_url_requires_https(self):
        with self.assertRaises(ValueError): validate_https_url("http://127.0.0.1/internal")
        with self.assertRaises(ValueError): validate_https_url("https://user:password@example.com")

    def test_custom_regex_is_rejected_to_prevent_redos(self):
        with self.assertRaises(ValueError): validate_detection({"selection": {"CommandLine|re": "(a+)+$"}, "condition": "selection"})

    def test_public_error_hides_sensitive_message(self):
        self.assertNotIn("actual-value", public_error(RuntimeError("API token actual-value failed")))

    def test_audit_entries_are_hash_chained(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "audit.jsonl"
            append_audit(path, "one", "success", {"token": "secret"})
            append_audit(path, "two", "failed", {})
            rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
            self.assertEqual(rows[0]["details"]["token"], "[REDACTED]")
            self.assertEqual(rows[1]["previous_hash"], rows[0]["entry_hash"])


if __name__ == "__main__":
    unittest.main()
