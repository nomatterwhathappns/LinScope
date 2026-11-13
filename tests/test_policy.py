from copy import deepcopy
from datetime import date
import json
from pathlib import Path
import tempfile
import unittest

from linscope.policy import apply_exceptions, load_policy, validate_policy


class PolicyTests(unittest.TestCase):
    def load(self, raw):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "policy.json"
            path.write_text(raw, encoding="utf-8")
            return load_policy(path)

    def test_valid_policy_and_no_mutation(self):
        policy = {"profile": "router", "checks": ["ssh", "network"], "exceptions": {
            "SSH-001": {"reason": "Approved access requirement", "expires": "2030-01-01"}}}
        original = deepcopy(policy)
        self.assertEqual(self.load(json.dumps(policy)), policy)
        validated = validate_policy(policy)
        validated["checks"].append("mac")
        self.assertEqual(policy, original)

    def test_duplicate_keys_rejected_at_every_level(self):
        for raw in ('{"profile":"server","profile":"desktop"}',
                    '{"exceptions":{"SSH-001":{"reason":"a","reason":"b","expires":"2030-01-01"}}}'):
            with self.subTest(raw=raw), self.assertRaisesRegex(ValueError, "Duplicate"):
                self.load(raw)

    def test_invalid_policy_rejected(self):
        invalid = [[], None, {"shell": "echo unsafe"}, {"profile": "windows"},
                   {"checks": []}, {"checks": "ssh"}, {"checks": ["ssh", "ssh"]},
                   {"checks": ["missing"]}, {"checks": [3]}, {"exceptions": []},
                   {"exceptions": {"SSH-001": {"reason": "", "expires": "2030-01-01"}}},
                   {"exceptions": {"SSH-001": {"reason": "   ", "expires": "2030-01-01"}}},
                   {"exceptions": {"SSH-001": {"reason": "x", "expires": "2030-1-1"}}},
                   {"exceptions": {"SSH-001": {"reason": "x", "expires": "2030-02-30"}}},
                   {"exceptions": {"SSH-001": {"reason": "x", "expires": 20300101}}},
                   {"exceptions": {"SSH-001": {"reason": "x", "expires": "2030-01-01", "ignore": True}}},
                   {"exceptions": {"SSH-001": {"reason": "x"}}},
                   {"exceptions": {"../../cmd": {"reason": "x", "expires": "2030-01-01"}}}]
        for policy in invalid:
            with self.subTest(policy=policy), self.assertRaises(ValueError):
                validate_policy(policy)

    def test_invalid_json_and_size_limit(self):
        with self.assertRaisesRegex(ValueError, "Invalid policy JSON"):
            self.load('{"profile":')
        with self.assertRaisesRegex(ValueError, "size limit"):
            self.load(" " * 262145)
        with self.assertRaisesRegex(ValueError, "size limit"):
            self.load(json.dumps({"profile": "server", "extra": "é" * 140000}, ensure_ascii=False))

    def test_active_expiry_day_and_expired_exception_visible(self):
        original = [{"id": "SSH-001", "status": "FAIL", "severity": "high", "evidence": "root login enabled"}]
        policy = {"exceptions": {"SSH-001": {"reason": "Temporary approval", "expires": "2030-01-01"}}}
        for day, active in ((date(2029, 12, 31), True), (date(2030, 1, 1), True), (date(2030, 1, 2), False)):
            with self.subTest(day=day):
                result = apply_exceptions(original, policy, today=day)
                self.assertEqual(result[0]["status"], "FAIL")
                self.assertEqual(result[0]["severity"], "high")
                self.assertEqual(result[0]["evidence"], original[0]["evidence"])
                self.assertEqual(result[0]["exception"]["active"], active)
        self.assertNotIn("exception", original[0])

    def test_old_exception_cannot_carry_over_without_policy(self):
        result = apply_exceptions([{"id": "SSH-001", "status": "WARN", "exception": {
            "active": True, "reason": "old", "expires": "2030-01-01"}}], {})
        self.assertNotIn("exception", result[0])


if __name__ == "__main__":
    unittest.main()
