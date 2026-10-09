def check_authorization_indicators(endpoints):
    """Identify endpoints that may need access-control review."""

    findings = []

    sensitive_paths = (
        "/admin",
        "/dashboard",
        "/account",
        "/profile",
        "/api",
    )

    for endpoint in endpoints:
        if not endpoint.get("success"):
            continue

        path = endpoint.get("path", "").lower().rstrip("/")
        status = endpoint.get("status_code")

        if path in sensitive_paths and status == 200:
            findings.append({
                "type": "Access Control Review",
                "severity": "INFO",
                "finding": f"Review access controls for {path}",
                "details": (
                    "This path returned HTTP 200. This alone does not "
                    "prove the endpoint is unprotected or vulnerable."
                ),
                "endpoint": endpoint.get("url", ""),
                "recommendation": (
                    "Using an authorized test account, verify that "
                    "authentication and permissions are enforced."
                ),
            })

    return findings


def run_authorization_checks(recon_result):
    """Review collected endpoints for access-control indicators."""

    if not recon_result.get("reachable"):
        return []

    return check_authorization_indicators(
        recon_result.get("endpoints", [])
    )
