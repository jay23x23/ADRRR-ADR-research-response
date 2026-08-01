import unittest

from content_adapters import json_records


class JsonLinesRegressionTests(unittest.TestCase):
    def test_multiple_json_objects_are_parsed_one_per_line(self):
        source = '{"event_id": 1, "name": "first"}\n{"event_id": 2, "name": "second"}\n'

        records = json_records(source)

        self.assertEqual(2, len(records))
        self.assertEqual([1, 2], [record["event_id"] for record in records])

    def test_regular_json_array_still_works(self):
        records = json_records('[{"event_id": 1}, {"event_id": 2}]')

        self.assertEqual(2, len(records))


if __name__ == "__main__":
    unittest.main()
