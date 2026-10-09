from urllib.parse import urlparse

API_PATHS = [
    "/openapi.json",
    "/swagger.json",
    "/api",
    "/api/v1",
    "/api/v2",
    "/graphql",
]


def check_api_endpoints(endpoints):
    """Identify potentially interesting API documentation endpoints."""

    findings = []

    for endpoint in endpoints:
        if not endpoint.get("success"):
            continue

        path = endpoint.get("path", "")
        status = endpoint.get("status_code")

        if path in API_PATHS and status == 200:
            findings.append({
                "type": "API Endpoint Discovery",
                "severity": "INFO",
                "finding": f"API-related endpoint responds: {path}",
                "details": (
                    f"The endpoint returned HTTP {status}. "
                    "This alone does not indicate a vulnerability."
                ),
                "endpoint": endpoint.get("url", ""),
                "recommendation": (
                    "Confirm that the endpoint is intended to be "
                    "publicly accessible and does not expose "
                    "sensitive information."
                )
            })

    return findings


def check_api_content_type(response):
    """Check whether a response appears to contain JSON."""

    findings = []

    if not response.get("success"):
        return findings

    headers = response.get("headers", {})
    content_type = next(
        (
            value for key, value in headers.items()
            if key.lower() == "content-type"
        ),
        ""
    )

    if "application/json" in content_type.lower():
        findings.append({
            "type": "API Response",
            "severity": "INFO",
            "finding": "JSON response detected",
            "details": (
                "The response uses a JSON content type. "
                "This is informational, not a vulnerability."
            ),
            "endpoint": response.get("url", ""),
            "recommendation": (
                "Review API authorization and data exposure "
                "separately; JSON responses are not inherently unsafe."
            )
        })

    return findings


def run_api_checks(recon_result):
    """Run passive checks against collected endpoint responses."""

    findings = []

    if not recon_result.get("reachable"):
        return findings

    endpoints = recon_result.get("endpoints", [])
    findings.extend(check_api_endpoints(endpoints))

    for endpoint in endpoints:
        findings.extend(check_api_content_type(endpoint))

    return findings
