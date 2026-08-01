import unittest
from datetime import timedelta

from workready_siem import DetectionEngine, Event, entropy, html_dashboard, incident_records, markdown_report, run
from response_playbooks import DETECTABLE_RULE_IDS, recommendations, solution_catalog, validate_playbooks


def event(event_type: str, **details) -> Event:
    raw = {"timestamp": "2026-07-31T01:00:00Z", "event_type": event_type, "host": "ws01", "user": "jose", **details}
    return Event.from_dict(raw)


class DetectionTests(unittest.TestCase):
    def test_entropy(self):
        self.assertLess(entropy("aaaaaaaaaaaaaaaa"), entropy("a8f2k9x7m3q1z6p4"))

    def test_office_shell(self):
        alerts = run([event("process", process_executable="powershell.exe", parent_executable="WINWORD.EXE")])
        self.assertEqual([item.rule_id for item in alerts], ["PROC-001"])

    def test_lsass_access(self):
        alerts = run([event("process_access", source_process="dump.exe", target_process="lsass.exe", granted_access="0x1010")])
        self.assertEqual(alerts[0].rule_id, "CRED-001")

    def test_brute_force_correlation(self):
        engine = DetectionEngine({"brute_force_failures": 2, "unusual_login_start_hour": 3, "unusual_login_end_hour": 4})
        failures = [event("authentication", outcome="failure", source_ip="1.1.1.1") for _ in range(2)]
        for item in failures:
            self.assertEqual(engine.process(item), [])
        alerts = engine.process(event("authentication", outcome="success", source_ip="1.1.1.1"))
        self.assertIn("AUTH-001", [item.rule_id for item in alerts])

    def test_private_lateral_movement(self):
        alerts = run([event("network", source_ip="10.0.0.2", destination_ip="10.0.0.3", destination_port=445)])
        self.assertEqual(alerts[0].rule_id, "NET-003")

    def test_regular_beacon(self):
        engine = DetectionEngine({"beacon_min_connections": 4})
        base = event("network", destination_ip="8.8.8.8", destination_port=443)
        alerts = []
        for index in range(4):
            current = Event(base.timestamp + timedelta(seconds=index * 30), base.event_type, base.host, base.user, base.source, base.details, base.raw)
            alerts.extend(engine.process(current))
        self.assertIn("NET-001", [item.rule_id for item in alerts])

    def test_run_key(self):
        alerts = run([event("registry", action="set", key="HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Demo")])
        self.assertEqual(alerts[0].rule_id, "REG-001")

    def test_unknown_event_is_ignored(self):
        self.assertEqual(run([event("made_up")]), [])

    def test_low_risk_alert_remains_reported(self):
        alerts = run([event("authentication", outcome="success")])
        cases = incident_records(alerts)
        self.assertEqual(len(cases), 1)
        self.assertEqual(cases[0]["risk"]["priority"], "P4")
        self.assertIn(cases[0]["case_id"], markdown_report(cases))

    def test_every_alert_has_five_coded_solutions(self):
        validate_playbooks()
        catalog = solution_catalog()
        self.assertEqual(set(catalog["alerts"]), DETECTABLE_RULE_IDS)
        for rule_id in DETECTABLE_RULE_IDS:
            items = recommendations(rule_id)
            self.assertEqual(len(items), 5)
            self.assertEqual(items[0]["solution_code"], f"{rule_id}-S01")
            self.assertEqual(items[-1]["solution_code"], f"{rule_id}-S05")

    def test_dashboard_displays_solution_codes(self):
        alerts = run([event("process", process_executable="powershell.exe", parent_executable="winword.exe")])
        page = html_dashboard(incident_records(alerts))
        self.assertIn("PROC-001-S01", page)
        self.assertIn("Risk to server/functionality", page)


if __name__ == "__main__":
    unittest.main()
