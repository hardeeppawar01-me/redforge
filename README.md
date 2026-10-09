# RedForge — Web & API Security Assessment Framework

RedForge is a Python-based security assessment framework designed to help security learners and penetration testers identify potential web application and API security issues in authorized testing environments.

## Features

- **Reconnaissance:** Checks target reachability and common web paths.
- **Security Headers:** Identifies missing recommended HTTP security headers.
- **Server Disclosure:** Detects potentially revealing server headers.
- **API Discovery:** Identifies common API and documentation endpoints.
- **JWT Inspection:** Inspects JWT header configuration indicators.
- **Cookie Security:** Checks observed cookies for selected security attributes.
- **Database Error Indicators:** Looks for database error messages in collected responses.
- **Access-Control Review:** Flags selected endpoints for manual permission checks.
- **Risk Scoring:** Calculates a simple severity-based prioritization score.
- **Report Generation:** Exports findings to HTML and JSON.

## Technology Stack

- Python 3
- Requests
- HTML and JSON
- unittest

## Project Structure

```text
redforge/
├── main.py
├── config.py
├── requirements.txt
├── README.md
├── .gitignore
├── modules/
│   ├── recon.py
│   ├── web_checks.py
│   ├── api_checks.py
│   ├── auth_checks.py
│   ├── injection_checks.py
│   ├── authorization_checks.py
│   ├── risk_engine.py
│   └── report_generator.py
├── reports/
└── tests/
    └── test_scanner.py
```

## Installation

Clone the repository and enter its directory:

```bash
git clone YOUR_GITHUB_REPOSITORY_URL
cd redforge
```

Create and activate a virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

## Usage

Run an assessment against a target you own or have explicit permission to test:

```bash
python3 main.py --target http://127.0.0.1:8000 --authorized
```

Choose a different output directory:

```bash
python3 main.py --target http://127.0.0.1:8000 --authorized --output reports
```

The `--authorized` flag is an explicit confirmation by the operator. It does not verify permission automatically.

## Reports

RedForge generates:

- **HTML:** A browser-readable summary of findings and recommendations.
- **JSON:** Structured findings for later analysis or automation.

Generated reports may contain target information. Review them for sensitive data before sharing.

## Testing

Run the automated tests:

```bash
python3 -m unittest discover -s tests -v
```

## Limitations

RedForge is a learning and assessment aid, not a substitute for a professional security audit.

- HTTP status codes and response patterns are indicators, not proof of vulnerabilities.
- JWT header inspection does not validate token signatures or server-side behavior.
- Access-control checks do not independently verify authorization enforcement.
- The risk score is a simple prioritization score, not CVSS.
- Findings require manual verification.

## Responsible Use

Only assess systems you own or have explicit authorization to test. Follow applicable laws, engagement rules, and scope restrictions.

## Disclaimer

The author is not responsible for unauthorized or unlawful use of this software.

