import unittest

from sigma_catalog_builder import applicable_environments, compile_catalog, family, stable_alert_code


WINDOWS_RULE = {
    "id": "11111111-1111-1111-1111-111111111111",
    "title": "Suspicious PowerShell Process",
    "description": "Training rule",
    "logsource": {"product": "windows", "category": "process_creation"},
    "tags": ["attack.execution"],
    "detection": {"selection": {"Image|endswith": "\\powershell.exe"}, "condition": "selection"},
}

LINUX_RULE = {
    "id": "22222222-2222-2222-2222-222222222222",
    "title": "Suspicious Linux Login",
    "logsource": {"product": "linux", "service": "sshd"},
    "tags": ["attack.initial-access"],
    "detection": {"selection": {"message|contains": "failure"}, "condition": "selection"},
}


class CatalogTests(unittest.TestCase):
    def test_environment_mapping(self):
        self.assertEqual(applicable_environments(WINDOWS_RULE), ["windows_11", "windows_server"])
        self.assertEqual(applicable_environments(LINUX_RULE), ["linux_mint", "ubuntu", "ubuntu_server"])

    def test_family_classification(self):
        self.assertEqual(family(WINDOWS_RULE), "process")
        self.assertEqual(family(LINUX_RULE), "identity")

    def test_stable_code(self):
        self.assertEqual(stable_alert_code(WINDOWS_RULE), stable_alert_code(WINDOWS_RULE))

    def test_exactly_five_solutions_per_alert(self):
        alerts, solutions = compile_catalog([WINDOWS_RULE, LINUX_RULE], "windows_11")
        self.assertEqual(len(alerts), 1)
        self.assertEqual(len(solutions), 5)
        self.assertEqual(alerts[0]["solution_codes"], [item["solution_code"] for item in solutions])

    def test_linux_rule_excluded_from_windows(self):
        alerts, solutions = compile_catalog([LINUX_RULE], "windows_11")
        self.assertEqual((alerts, solutions), ([], []))


if __name__ == "__main__":
    unittest.main()
