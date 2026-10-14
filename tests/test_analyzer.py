import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO

from analyzer import analyze_logs, main


def access_log(ip, timestamp, request, status=200):
    return '{} - - [{}] "{}" {} 123\n'.format(ip, timestamp, request, status)


class AnalyzeLogsTests(unittest.TestCase):
    def analyze_text(self, content, **kwargs):
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", delete=False
        ) as log_file:
            log_file.write(content)
            path = log_file.name
        try:
            return analyze_logs(path, **kwargs)
        finally:
            os.unlink(path)

    def test_analyzes_ipv6_and_encoded_attack_patterns(self):
        content = access_log(
            "2001:db8::1",
            "13/Oct/2026:10:00:01 +0000",
            "GET /login?q=%55NION%20SELECT%20x HTTP/1.1",
            500,
        )

        result = self.analyze_text(content)

        self.assertEqual(result.total_requests, 1)
        self.assertEqual(result.suspicious_requests[0].ip, "2001:db8::1")
        self.assertEqual(
            result.suspicious_requests[0].pattern, "SQL injection (UNION SELECT)"
        )

    def test_counts_thresholds_over_entire_file_by_default(self):
        content = "".join(
            access_log(
                "203.0.113.5",
                "13/Oct/2026:10:{:02d}:00 +0000".format(minute),
                "GET /login HTTP/1.1",
                401,
            )
            for minute in (0, 1, 10)
        )

        result = self.analyze_text(content, failed_login_threshold=3)

        self.assertEqual(result.failed_logins["203.0.113.5"], 3)
        self.assertEqual(result.failed_login_alerts["203.0.113.5"], 3)

    def test_window_uses_peak_events_inside_window(self):
        content = "".join(
            access_log(
                "203.0.113.5",
                "13/Oct/2026:10:{:02d}:00 +0000".format(minute),
                "GET /login HTTP/1.1",
                401,
            )
            for minute in (0, 1, 10)
        )

        result = self.analyze_text(content, failed_login_threshold=3, window_minutes=2)

        self.assertEqual(result.failed_logins["203.0.113.5"], 3)
        self.assertEqual(result.failed_login_alerts, {})

    def test_counts_unrecognized_lines_and_decodes_traversal(self):
        content = "malformed log line\n" + access_log(
            "198.51.100.7",
            "13/Oct/2026:10:00:01 +0000",
            "GET /%2e%2e%2fetc/passwd HTTP/1.1",
            400,
        )

        result = self.analyze_text(content)

        self.assertEqual(result.unparsed_lines, 1)
        self.assertEqual(result.suspicious_requests[0].pattern, "Path traversal")
        self.assertEqual(len(result.suspicious_requests), 2)

    def test_cli_emits_json(self):
        log_path = os.path.join(os.path.dirname(__file__), "..", "sample-access.log")
        output = StringIO()

        with redirect_stdout(output):
            exit_code = main([log_path, "--format", "json"])

        report = json.loads(output.getvalue())
        self.assertEqual(exit_code, 0)
        self.assertEqual(report["total_requests"], 9)
        self.assertIn("203.0.113.5", report["failed_login_alerts"])


if __name__ == "__main__":
    unittest.main()
