import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from rules import RuleError, RuleSet  # noqa: E402

RULES = os.path.join(os.path.dirname(__file__), "..", "rules.json")


def ev(**kw):
    base = {"image_name": "x.exe", "image_path": "C:\\x.exe", "pid": 1, "ppid": 0}
    base.update(kw)
    return base


class RuleTests(unittest.TestCase):
    def setUp(self):
        self.rs = RuleSet.load(RULES)

    def names(self, e):
        return {r["rule_id"] for r in self.rs.match(e)}

    def test_exact_basename_not_substring(self):
        self.assertIn("AEG-WIN-004", self.names(ev(image_name="cmd.exe")))
        self.assertEqual(self.names(ev(image_name="xcmd.exe.txt")), set())
        self.assertEqual(self.names(ev(image_name="notcmd.exe")), set())

    def test_case_insensitive(self):
        self.assertIn("AEG-WIN-001", self.names(ev(image_name="MiMiKaTz.EXE")))

    def test_and_requires_all(self):
        self.assertNotIn("AEG-WIN-005", self.names(ev(image_name="cmd.exe")))
        hit = self.names(ev(image_name="cmd.exe", parent_image_name="nginx.exe"))
        self.assertIn("AEG-WIN-005", hit)

    def test_missing_field_never_matches(self):
        # command_line is not collected yet: encoded-powershell rule must stay silent
        self.assertNotIn("AEG-WIN-006", self.names(ev(image_name="powershell.exe")))
        hit = self.names(ev(image_name="powershell.exe", command_line="powershell -ExecutionPolicy Bypass -enc AAA"))
        self.assertIn("AEG-WIN-006", hit)

    def test_disabled_rule_skipped(self):
        self.assertNotIn("AEG-WIN-008", self.names(ev(image_name="whoami.exe")))

    def test_or_and_nesting(self):
        rs = RuleSet([{"rule_id": "T", "name": "t", "severity": "LOW", "condition": "OR", "criteria": [
            {"field": "pid", "operator": "gt", "value": 100},
            {"condition": "AND", "criteria": [
                {"field": "image_name", "operator": "endswith", "value": ".ps1"},
                {"field": "ppid", "operator": "equals", "value": 4}]}]}])
        self.assertTrue(rs.match(ev(pid=500)))
        self.assertTrue(rs.match(ev(image_name="a.ps1", ppid=4)))
        self.assertFalse(rs.match(ev(image_name="a.ps1", ppid=5)))

    def test_bad_rules_rejected_at_load(self):
        with self.assertRaises(RuleError):
            RuleSet([{"rule_id": "B", "name": "b", "severity": "LOW",
                      "criteria": [{"field": "a", "operator": "nope", "value": 1}]}])
        with self.assertRaises(RuleError):
            RuleSet([{"rule_id": "B", "name": "b", "severity": "BOGUS", "criteria": []}])


if __name__ == "__main__":
    unittest.main()
