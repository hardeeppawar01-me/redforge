import base64
import json


def inspect_jwt(token):
    """Inspect JWT structure and header without validating or using it."""

    findings = []

    parts = token.split(".")

    if len(parts) != 3:
        return [{
            "type": "JWT Inspection",
            "severity": "INFO",
            "finding": "Input is not a standard three-part JWT",
            "details": "Expected header.payload.signature format."
        }]

    try:
        header_part = parts[0]
        padding = "=" * (-len(header_part) % 4)

        decoded = base64.urlsafe_b64decode(
            header_part + padding
        )

        header = json.loads(decoded.decode("utf-8"))

    except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
        return [{
            "type": "JWT Inspection",
            "severity": "INFO",
            "finding": "JWT header could not be decoded",
            "details": "The token may be malformed."
        }]

    algorithm = str(header.get("alg", "")).lower()

    if algorithm == "none":
        findings.append({
            "type": "JWT Configuration",
            "severity": "HIGH",
            "finding": "JWT uses the none algorithm",
            "details": (
                "The token header specifies no signing algorithm. "
                "This is a risk indicator, not proof the server accepts it."
            ),
            "recommendation": (
                "Require approved signing algorithms and validate "
                "the signature server-side."
            )
        })

    if not algorithm:
        findings.append({
            "type": "JWT Configuration",
            "severity": "MEDIUM",
            "finding": "JWT algorithm is missing",
            "details": "The decoded header has no alg field.",
            "recommendation": (
                "Validate token format and enforce an explicit "
                "allowlist of signing algorithms."
            )
        })

    if not findings:
        findings.append({
            "type": "JWT Inspection",
            "severity": "INFO",
            "finding": "JWT header inspected",
            "details": (
                f"Header algorithm: {header.get('alg', 'unspecified')}. "
                "This inspection does not validate the signature, "
                "claims, or server-side acceptance."
            ),
            "recommendation": (
                "Verify signature validation, issuer, audience, "
                "expiration, and algorithm allowlisting in the application."
            )
        })

    return findings


def check_auth_response(response):
    """Perform passive checks on an HTTP response."""

    findings = []

    if not response or not response.get("success"):
        return findings

    headers = response.get("headers", {})
    normalized = {
        key.lower(): value
        for key, value in headers.items()
    }

    if "set-cookie" in normalized:
        cookie_header = normalized["set-cookie"].lower()

        if "secure" not in cookie_header:
            findings.append({
                "type": "Cookie Security",
                "severity": "MEDIUM",
                "finding": "Cookie may lack Secure attribute",
                "details": (
                    "A Set-Cookie response was observed without "
                    "a Secure attribute in the header value."
                ),
                "recommendation": (
                    "For cookies carrying sensitive session data, "
                    "set Secure when HTTPS is used."
                )
            })

        if "httponly" not in cookie_header:
            findings.append({
                "type": "Cookie Security",
                "severity": "LOW",
                "finding": "Cookie may lack HttpOnly attribute",
                "details": (
                    "A Set-Cookie response was observed without "
                    "an HttpOnly attribute in the header value."
                ),
                "recommendation": (
                    "Set HttpOnly on session cookies that do not "
                    "need to be accessed by client-side JavaScript."
                )
            })

    return findings

