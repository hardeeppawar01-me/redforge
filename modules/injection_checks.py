import re


DATABASE_ERROR_PATTERNS = [
    ("MySQL", r"you have an error in your sql syntax"),
    ("PostgreSQL", r"postgresql.*error|syntax error at or near"),
    ("SQLite", r"sqlite(?:3)?\.operationalerror|sqlite error"),
    ("Microsoft SQL Server", r"unclosed quotation mark after the character string"),
    ("Oracle", r"ora-\d{5}"),
]


def detect_database_errors(response_text):
    """Look for database error messages in an existing response."""

    findings = []

    if not isinstance(response_text, str) or not response_text:
        return findings

    for database, pattern in DATABASE_ERROR_PATTERNS:
        if re.search(pattern, response_text, re.IGNORECASE):
            findings.append({
                "type": "Possible SQL Error Disclosure",
                "severity": "MEDIUM",
                "finding": f"Possible {database} error message detected",
                "details": (
                    "The response resembles a database error. "
                    "This does not prove SQL injection."
                ),
                "recommendation": (
                    "Review error handling, use parameterized queries, "
                    "and avoid exposing internal database errors."
                ),
            })

    return findings


def run_injection_checks(recon_result):
    """Check responses already collected during reconnaissance."""

    findings = []

    if not recon_result.get("reachable"):
        return findings

    responses = [recon_result.get("root", {})]
    responses.extend(recon_result.get("endpoints", []))

    for response in responses:
        if not response.get("success"):
            continue

        response_findings = detect_database_errors(
            response.get("text", "")
        )

        for finding in response_findings:
            finding["endpoint"] = response.get("url", "")

        findings.extend(response_findings)

    return findings
