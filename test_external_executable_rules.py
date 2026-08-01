import unittest

from external_executable_rules import translate


class ExternalExecutableRuleTests(unittest.TestCase):
    def test_simple_elastic_eql_is_promoted(self):
        rule = translate({"source": "elastic", "content_id": "e1", "title": "Test",
                          "query": 'process where process.name == "example.exe"', "severity": "medium"})
        self.assertEqual("example.exe", rule["detection"]["selection"]["process.name"])

    def test_simple_splunk_field_match_is_promoted(self):
        rule = translate({"source": "splunk", "content_id": "s1", "title": "Test",
                          "query": "index=main Image=*powershell.exe", "severity": "high"})
        self.assertEqual("powershell.exe", rule["detection"]["selection"]["process.executable|endswith"])

    def test_aggregation_is_never_promoted(self):
        with self.assertRaisesRegex(ValueError, "aggregation"):
            translate({"source": "sentinel", "content_id": "m1", "title": "Test",
                       "query": "SigninLogs | summarize count() by UserPrincipalName"})


if __name__ == "__main__":
    unittest.main()
