import unittest

from modules.web_checks import check_security_headers
from modules.injection_checks import detect_database_errors
from modules.authorization_checks import check_authorization_indicators
from modules.risk_engine import calculate_risk, prioritize_findings
from modules.report_generator import generate_reports


class TestRedForge(unittest.TestCase):

    def test_missing_security_headers(self):
        findings = check_security_headers({})
        self.assertTrue(len(findings) > 0)
        self.assertEqual(
            findings[0]["type"],
            "Missing Security Header",
        )

    def test_database_error_indicator(self):
        findings = detect_database_errors(
            "You have an error in your SQL syntax"
        )
        self.assertTrue(findings)
        self.assertEqual(findings[0]["severity"], "MEDIUM")

    def test_authorization_indicator(self):
        findings = check_authorization_indicators([
            {
                "success": True,
                "path": "/admin",
                "status_code": 200,
                "url": "http://localhost/admin",
            }
        ])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "INFO")

    def test_risk_score(self):
        result = calculate_risk([
            {"severity": "HIGH"},
            {"severity": "MEDIUM"},
            {"severity": "LOW"},
        ])
        self.assertEqual(result["risk_score"], 13)
        self.assertEqual(result["risk_level"], "LOW")

    def test_prioritization(self):
        findings = [
            {"severity": "LOW"},
            {"severity": "HIGH"},
            {"severity": "MEDIUM"},
        ]
        ordered = prioritize_findings(findings)
        self.assertEqual(
            [item["severity"] for item in ordered],
            ["HIGH", "MEDIUM", "LOW"],
        )


if __name__ == "__main__":
    unittest.main()

