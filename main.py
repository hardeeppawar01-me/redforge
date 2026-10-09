import argparse
import json
import sys

from config import DEFAULT_CONFIG
from modules.recon import ReconScanner
from modules.web_checks import run_web_checks
from modules.api_checks import run_api_checks
from modules.auth_checks import check_auth_response
from modules.injection_checks import run_injection_checks
from modules.authorization_checks import run_authorization_checks
from modules.risk_engine import calculate_risk, prioritize_findings
from modules.report_generator import generate_reports


def main():
    parser = argparse.ArgumentParser(
        description="RedForge - Authorized Web & API Security Assessment"
    )

    parser.add_argument(
        "--target",
        required=True,
        help="Target URL you are authorized to assess",
    )

    parser.add_argument(
        "--authorized",
        action="store_true",
        help="Confirm you have permission to assess this target",
    )

    parser.add_argument(
        "--output",
        default="reports",
        help="Directory for generated reports",
    )

    args = parser.parse_args()

    if not args.authorized:
        parser.error(
            "Confirm authorization with --authorized before scanning."
        )

    try:
        scanner = ReconScanner(args.target, DEFAULT_CONFIG)
    except ValueError as error:
        parser.error(str(error))

    print("[*] RedForge assessment starting")
    print(f"[*] Target: {scanner.target}")

    recon_result = scanner.collect()

    if not recon_result.get("reachable"):
        print("[!] Target could not be reached.")
        print(json.dumps(recon_result.get("root", {}), indent=2))
        return 1

    print("[+] Target responded. Running passive checks...")

    findings = []

    findings.extend(run_web_checks(recon_result))
    findings.extend(run_api_checks(recon_result))
    findings.extend(run_injection_checks(recon_result))
    findings.extend(run_authorization_checks(recon_result))

    root_response = recon_result.get("root", {})
    findings.extend(check_auth_response(root_response))

    findings = prioritize_findings(findings)
    risk_summary = calculate_risk(findings)

    report_paths = generate_reports(
        target=scanner.target,
        findings=findings,
        risk_summary=risk_summary,
        output_dir=args.output,
    )

    print("\n========== REDFORGE SUMMARY ==========")
    print(f"Findings: {risk_summary['total_findings']}")
    print(f"Risk score: {risk_summary['risk_score']}/100")
    print(f"Risk level: {risk_summary['risk_level']}")
    print("\nReports generated:")

    for report_type, path in report_paths.items():
        print(f"  {report_type}: {path}")

    print("\n[!] Review findings manually; indicators are not proof.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
