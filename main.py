from __future__ import annotations

import argparse
from collections.abc import Sequence
import sys

from core.auth import create_session, resolve_region
from core.engine import ScanEngine, load_rules
from core.models import ScanResult, Severity
from reporters.html_reporter import HTMLReporter
from reporters.json_reporter import JSONReporter


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cloud-misconfig-scanner",
        description="Scan AWS accounts (S3, IAM, EC2) for common security misconfigurations.",
    )
    parser.add_argument(
        "--profile",
        help="AWS CLI profile name (optional; defaults to standard boto3 credential chain).",
    )
    parser.add_argument(
        "--region",
        help="Single AWS region to scan (defaults to session region or us-east-1).",
    )
    parser.add_argument(
        "--regions",
        help="Comma-separated list of AWS regions to scan (overrides --region).",
    )
    parser.add_argument(
        "--services",
        default="s3,iam,ec2",
        help="Comma-separated list of services to scan (default: s3,iam,ec2).",
    )
    parser.add_argument(
        "--rules",
        default="config/rules.yaml",
        help="Path to YAML rules definition file (default: config/rules.yaml).",
    )
    parser.add_argument(
        "--format",
        choices=["console", "json", "html"],
        default="console",
        help="Output report format (default: console).",
    )
    parser.add_argument(
        "--output",
        help="Output file path (required when --format is json or html).",
    )
    parser.add_argument(
        "--fail-on",
        choices=[s.value for s in Severity],
        help="Exit with code 1 if any FAIL finding meets or exceeds this severity.",
    )
    return parser


def print_console_report(result: ScanResult) -> None:
    summary = result.summary()
    print(
        f"Scan completed for account '{result.account_id}' "
        f"(services: {', '.join(result.scanned_services)} | "
        f"regions: {', '.join(result.scanned_regions)})"
    )
    print(
        f"Summary: total={summary['total']} "
        f"PASS={summary['PASS']} FAIL={summary['FAIL']} ERROR={summary['ERROR']}"
    )
    for finding in result.findings:
        print(
            f"[{finding.status.value}] [{finding.severity.value}] "
            f"{finding.rule_id} ({finding.service}/{finding.region}) "
            f"{finding.resource_id}: {finding.message}"
        )


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.format in {"json", "html"} and not args.output:
        parser.error(f"--output is required when --format is '{args.format}'.")

    rules = load_rules(args.rules)
    session = create_session(profile_name=args.profile, region_name=args.region)

    if args.regions:
        regions = [r.strip() for r in args.regions.split(",") if r.strip()]
    else:
        regions = [resolve_region(session, args.region)]

    services = [s.strip().lower() for s in args.services.split(",") if s.strip()]

    engine = ScanEngine(
        session=session,
        rules=rules,
        regions=regions,
        services=services,
    )
    result = engine.run()

    if args.format == "json":
        path = JSONReporter().export(result, args.output)
        print(f"JSON report written to {path}")
    elif args.format == "html":
        path = HTMLReporter().export(result, args.output)
        print(f"HTML report written to {path}")
    else:
        print_console_report(result)

    if args.fail_on:
        threshold = Severity(args.fail_on.upper())
        if result.has_failures_at_or_above(threshold):
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
