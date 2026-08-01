import tempfile
import unittest
from pathlib import Path

from cross_source_siem import Store, UnifiedRecord, correlate


def record(event_id, timestamp, source_type, **values):
    return UnifiedRecord.from_dict({"event_id": event_id, "timestamp": timestamp, "source_type": source_type, "title": values.pop("title", event_id), **values})


class CorrelationTests(unittest.TestCase):
    def test_edr_email_firewall_correlation(self):
        rows = [
            record("EMAIL", "2026-07-31T09:00:00Z", "email", user="jose", source_ip="203.0.113.10"),
            record("EDR", "2026-07-31T09:03:00Z", "edr", user="jose", host="laptop-01", source_ip="203.0.113.10"),
            record("FW", "2026-07-31T09:04:00Z", "firewall", host="laptop-01", bytes_out=200_000_000),
        ]
        items = correlate(rows, minutes=5)
        self.assertEqual(len(items), 1)
        self.assertIn("email", items[0].reason)
        self.assertGreaterEqual(items[0].risk_score, 75)

    def test_time_alone_does_not_correlate(self):
        rows = [record("EDR", "2026-07-31T09:00:00Z", "edr", host="one"), record("FW", "2026-07-31T09:01:00Z", "firewall", host="two")]
        self.assertEqual(correlate(rows), [])

    def test_raw_gate(self):
        with tempfile.TemporaryDirectory() as folder:
            with Store(Path(folder) / "events.db") as store:
                raw = record("RAW", "2026-07-31T09:00:00Z", "edr", record_type="raw", host="ordinary")
                accepted, dropped = store.ingest([raw], critical_hosts=set())
            self.assertEqual((accepted, dropped), (0, 1))


if __name__ == "__main__":
    unittest.main()
