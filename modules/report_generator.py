import json
from datetime import datetime, timezone
from html import escape
from pathlib import Path


def generate_reports(
    target,
    findings,
    risk_summary,
    output_dir="reports",
):
    """Generate HTML and JSON reports from assessment findings."""

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now(timezone.utc)
    report_id = timestamp.strftime("%Y%m%d_%H%M%S")

    report_data = {
        "tool": "RedForge",
        "generated_at": timestamp.isoformat(),
        "target": target,
        "risk_summary": risk_summary,
        "total_findings": len(findings),
        "findings": findings,
    }

    json_file = output_path / f"redforge_{report_id}.json"
    html_file = output_path / f"redforge_{report_id}.html"

    json_file.write_text(
        json.dumps(report_data, indent=4),
        encoding="utf-8",
    )

    rows = []

    for finding in findings:
        severity = escape(
            str(finding.get("severity", "INFO")).upper()
        )
        title = escape(str(finding.get("finding", "Untitled finding")))
        details = escape(str(finding.get("details", "")))
        endpoint = escape(str(finding.get("endpoint", "")))
        recommendation = escape(
            str(finding.get("recommendation", "Review manually."))
        )

        rows.append(f"""
        <tr>
            <td>{severity}</td>
            <td>{title}</td>
            <td>{details}</td>
            <td>{endpoint}</td>
            <td>{recommendation}</td>
        </tr>
        """)

    findings_html = "\n".join(rows)

    if not findings_html:
        findings_html = (
            '<tr><td colspan="5">No findings recorded.</td></tr>'
        )

    target_html = escape(str(target))
    risk_score = escape(str(risk_summary.get("risk_score", 0)))
    risk_level = escape(str(risk_summary.get("risk_level", "INFO")))
    total_findings = len(findings)

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>RedForge Security Assessment</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 32px;
            background: #f4f6fa;
            color: #202938;
        }}
        h1 {{ color: #b42318; }}
        .summary {{
            display: flex;
            flex-wrap: wrap;
            gap: 16px;
            margin: 24px 0;
        }}
        .card {{
            background: white;
            padding: 18px;
            border-radius: 8px;
            min-width: 150px;
            box-shadow: 0 2px 8px #00000012;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            background: white;
        }}
        th, td {{
            text-align: left;
            padding: 12px;
            border: 1px solid #e0e4ea;
            overflow-wrap: anywhere;
        }}
        th {{ background: #202938; color: white; }}
        tr:nth-child(even) {{ background: #f8fafc; }}
        footer {{ margin-top: 24px; color: #667085; }}
    </style>
</head>
<body>
    <h1>RedForge Security Assessment</h1>
    <p><strong>Target:</strong> {target_html}</p>
    <p><strong>Generated:</strong> {escape(timestamp.isoformat())}</p>

    <div class="summary">
        <div class="card">
            <strong>Risk score</strong>
            <h2>{risk_score}/100</h2>
        </div>
        <div class="card">
            <strong>Risk level</strong>
            <h2>{risk_level}</h2>
        </div>
        <div class="card">
            <strong>Total findings</strong>
            <h2>{total_findings}</h2>
        </div>
    </div>

    <h2>Findings and Recommendations</h2>
    <table>
        <thead>
            <tr>
                <th>Severity</th>
                <th>Finding</th>
                <th>Details</th>
                <th>Endpoint</th>
                <th>Recommendation</th>
            </tr>
        </thead>
        <tbody>
            {findings_html}
        </tbody>
    </table>

    <footer>
        RedForge is an assessment aid. Findings require manual validation.
    </footer>
</body>
</html>
"""

    html_file.write_text(html_content, encoding="utf-8")

    return {
        "json_report": str(json_file),
        "html_report": str(html_file),
    }
