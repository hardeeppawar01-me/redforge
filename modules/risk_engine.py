SEVERITY_WEIGHTS = {
    "CRITICAL": 10,
    "HIGH": 7,
    "MEDIUM": 4,
    "LOW": 2,
    "INFO": 0,
}


def calculate_risk(findings):
    """Calculate a simple risk score from collected findings."""

    score = sum(
        SEVERITY_WEIGHTS.get(
            str(finding.get("severity", "INFO")).upper(), 0
        )
        for finding in findings
    )

    # Cap the score at 100 for easier reporting.
    score = min(score, 100)

    if score >= 70:
        level = "CRITICAL"
    elif score >= 40:
        level = "HIGH"
    elif score >= 20:
        level = "MEDIUM"
    elif score > 0:
        level = "LOW"
    else:
        level = "INFO"

    return {
        "risk_score": score,
        "risk_level": level,
        "total_findings": len(findings),
        "severity_counts": {
            severity: sum(
                1
                for finding in findings
                if str(finding.get("severity", "INFO")).upper()
                == severity
            )
            for severity in SEVERITY_WEIGHTS
        },
    }


def prioritize_findings(findings):
    """Sort findings from highest to lowest severity."""

    return sorted(
        findings,
        key=lambda finding: SEVERITY_WEIGHTS.get(
            str(finding.get("severity", "INFO")).upper(), 0
        ),
        reverse=True,
    )
