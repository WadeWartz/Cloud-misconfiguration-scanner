from __future__ import annotations

from pathlib import Path

import boto3
import yaml

from core.auth import get_account_id, resolve_region
from core.models import Finding, Rule, ScanResult, utc_now_iso
from scanners.base_scanner import BaseScanner
from scanners.ec2_scanner import EC2Scanner
from scanners.iam_scanner import IAMScanner
from scanners.s3_scanner import S3Scanner

SCANNER_REGISTRY: dict[str, type[BaseScanner]] = {
    "s3": S3Scanner,
    "iam": IAMScanner,
    "ec2": EC2Scanner,
}


def load_rules(rules_path: str | Path) -> list[Rule]:
    """Load and parse scanning rules from a YAML file."""
    path = Path(rules_path)
    with path.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}

    raw_rules = data.get("rules", []) if isinstance(data, dict) else data
    return [Rule.from_dict(item) for item in raw_rules]


class ScanEngine:
    """Central orchestrator that loads rules, runs service scanners, and aggregates results."""

    def __init__(
        self,
        session: boto3.Session,
        rules: list[Rule],
        regions: list[str] | None = None,
        services: list[str] | None = None,
    ) -> None:
        self.session = session
        self.rules = [r for r in rules if r.enabled]
        default_region = resolve_region(session)
        self.regions = [r.strip() for r in (regions or [default_region]) if r.strip()]

        requested_services = (
            [s.strip().lower() for s in services if s.strip()]
            if services
            else list(SCANNER_REGISTRY.keys())
        )
        self.services = [s for s in requested_services if s in SCANNER_REGISTRY]

    def run(self) -> ScanResult:
        started_at = utc_now_iso()
        account_id = get_account_id(self.session)
        findings: list[Finding] = []

        for service_name in self.services:
            scanner_cls = SCANNER_REGISTRY[service_name]
            if scanner_cls.is_global:
                scanner = scanner_cls(
                    session=self.session,
                    rules=self.rules,
                    region="global",
                )
                findings.extend(scanner.scan())
            else:
                for region in self.regions:
                    scanner = scanner_cls(
                        session=self.session,
                        rules=self.rules,
                        region=region,
                    )
                    findings.extend(scanner.scan())

        return ScanResult(
            account_id=account_id,
            scanned_regions=self.regions,
            scanned_services=self.services,
            started_at=started_at,
            finished_at=utc_now_iso(),
            findings=findings,
        )
