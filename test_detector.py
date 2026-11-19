import unittest
import tempfile
from pathlib import Path
from unittest.mock import patch

import detector


class TestCyberThreatDetector(unittest.TestCase):

    def run_log_test(self, log_content):
        with tempfile.TemporaryDirectory() as temp_dir:

            log_file = Path(temp_dir) / "test_logs.txt"
            log_file.write_text(log_content, encoding="utf-8")

            with patch.object(detector, "LOG_FILE", log_file):
                return detector.read_logs()

    def test_valid_log_entry(self):
        logs, invalid_logs = self.run_log_test(
            "2026-11-12 09:00:00 LOGIN_FAILED 192.168.1.10"
        )

        self.assertEqual(len(logs), 1)
        self.assertEqual(len(invalid_logs), 0)

    def test_incomplete_log_entry(self):
        logs, invalid_logs = self.run_log_test(
            "INVALID LOG ENTRY"
        )

        self.assertEqual(len(logs), 0)
        self.assertIn("Incomplete log entry", invalid_logs[0])

    def test_invalid_timestamp(self):
        logs, invalid_logs = self.run_log_test(
            "2026-99-12 09:00:00 LOGIN_FAILED 192.168.1.10"
        )

        self.assertEqual(len(logs), 0)
        self.assertIn("Invalid timestamp", invalid_logs[0])

    def test_invalid_ip_address(self):
        logs, invalid_logs = self.run_log_test(
            "2026-11-12 09:00:00 LOGIN_FAILED invalid-ip"
        )

        self.assertEqual(len(logs), 0)
        self.assertIn("Invalid IP address", invalid_logs[0])

    def test_unknown_event_type(self):
        logs, invalid_logs = self.run_log_test(
            "2026-11-12 09:00:00 UNKNOWN_EVENT 192.168.1.10"
        )

        self.assertEqual(len(logs), 0)
        self.assertIn("Unknown event type", invalid_logs[0])

    def test_valid_logs_continue_after_invalid_entries(self):
        log_content = (
            "2026-11-12 09:00:00 LOGIN_FAILED 192.168.1.10\n"
            "INVALID LOG ENTRY\n"
            "2026-11-12 09:01:00 PORT_SCAN 10.0.0.5"
        )

        logs, invalid_logs = self.run_log_test(log_content)

        self.assertEqual(len(logs), 2)
        self.assertEqual(len(invalid_logs), 1)

    def test_ip_risk_classification(self):
        activity = {
            "DOS_ATTACK": 5,
            "LOGIN_FAILED": 0,
            "PORT_SCAN": 0
        }

        self.assertEqual(
            detector.classify_ip_risk(activity),
            "CRITICAL RISK"
        )

    def test_custom_brute_force_threshold(self):

        logs = [
            "2026-11-12 09:00:00 LOGIN_FAILED 192.168.1.10",
            "2026-11-12 09:01:00 LOGIN_FAILED 192.168.1.10"
        ]

        custom_thresholds = {
            "BRUTE_FORCE": 2,
            "PORT_SCAN": 3,
            "DOS_ATTACK": 5
        }

        with patch.dict(detector.DETECTION_THRESHOLDS, custom_thresholds):

            threats, total_events, ip_activity, ip_risks = detector.analyze_logs(logs)

        self.assertEqual(len(threats), 1)
        self.assertEqual(threats[0]["type"], "Brute Force Attack")
        self.assertEqual(ip_risks["192.168.1.10"], "HIGH RISK")
    def test_risk_score_calculation(self):
        self.assertEqual(detector.calculate_risk_score("LOW"), 25)
        self.assertEqual(detector.calculate_risk_score("MEDIUM"), 50)
        self.assertEqual(detector.calculate_risk_score("HIGH"), 75)
        self.assertEqual(detector.calculate_risk_score("CRITICAL"), 95)
        self.assertEqual(detector.calculate_risk_score("UNKNOWN"), 0)   


if __name__ == "__main__":
    unittest.main()