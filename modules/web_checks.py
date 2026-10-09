from urllib.parse import urlparse

from config import DEFAULT_CONFIG


def check_security_headers(headers):
    """Identify missing recommended HTTP security headers."""

    findings = []

    normalized = {
        key.lower(): value
        for key, value in headers.items()
    }

    for header in DEFAULT_CONFIG.security_headers:
        if header.lower() not in normalized:
            findings.append({
                "type": "Missing Security Header",
                "severity": "LOW",
                "finding": f"Missing {header} header",
                "details": (
                    f"The HTTP response does not include "
                    f"the {header} security header."
                ),
                "recommendation": (
                    f"Review whether {header} should be configured "
                    "for this application."
                )
            })

    return findings


def check_server_disclosure(headers):
    """Identify server headers that disclose implementation details."""

    findings = []

    for key, value in headers.items():
        if key.lower() == "server" and value.strip():
            findings.append({
                "type": "Information Disclosure",
                "severity": "INFO",
                "finding": "Server header disclosed",
                "details": f"The server returned: {value}",
                "recommendation": (
                    "Consider minimizing unnecessary server "
                    "version details in response headers."
                )
            })

    return findings


def run_web_checks(recon_result):
    """Run passive checks on an already-collected HTTP response."""

    findings = []

    if not recon_result.get("reachable"):
        return findings

    root = recon_result.get("root", {})

    if not root.get("success"):
        return findings

    headers = root.get("headers", {})

    findings.extend(check_security_headers(headers))
    findings.extend(check_server_disclosure(headers))

    return findings
