import unittest

from check_b7_coverage import check_log, required_cells


class CoverageGateTests(unittest.TestCase):
    def setUp(self):
        self.cells = required_cells()
        self.log = "\n".join(f"--- PASS: {name} (0.01s)" for name in self.cells)

    def test_complete(self):
        result = check_log(self.log)
        self.assertEqual(result["passed"], len(self.cells))
        self.assertFalse(result["missing"] or result["bad"] or result["nonpassing_descendants"])

    def test_missing_overlap(self):
        name = "TestB7CombinedProfiles/sender/persistent-xudp/working-node/wave1/2-second/cancel"
        result = check_log(self.log.replace(f"--- PASS: {name} (0.01s)", ""))
        self.assertEqual(result["missing"], [name])

    def test_missing_second_repetition(self):
        name = self.cells[3]
        doubled = self.log + "\n" + self.log
        self.assertFalse(check_log(doubled, 2)["incomplete_repetitions"])
        result = check_log(doubled.replace(f"--- PASS: {name} (0.01s)", "", 1), 2)
        self.assertEqual(result["incomplete_repetitions"], {name: 1})

    def test_failed_attempt_is_not_hidden_by_later_pass(self):
        name = self.cells[3]
        result = check_log(self.log + f"\n--- FAIL: {name} (0.01s)")
        self.assertEqual(result["bad"][name], ["FAIL", "PASS"])

    def test_skip_and_unlisted_failed_descendant(self):
        name = "TestB7CombinedProfiles/native/vless/extra"
        for action in ("SKIP", "FAIL"):
            result = check_log(self.log + f"\n--- {action}: {name} (0.01s)")
            self.assertIn(name, result["nonpassing_descendants"])


if __name__ == "__main__":
    unittest.main()
