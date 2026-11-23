from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def rank(self) -> int:
        ranks = {
            Severity.INFO: 1,
            Severity.LOW: 2,
            Severity.MEDIUM: 3,
            Severity.HIGH: 4,
            Severity.CRITICAL: 5,
        }
        return ranks[self]


class Status(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    ERROR = "ERROR"


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class Rule:
    id: str
    service: str
    title: str
    severity: Severity
    enabled: bool = True
    description: str = ""
    remediation: str = ""
    params: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Rule:
        raw_severity = data.get("severity", "MEDIUM")
        severity = (
            raw_severity
            if isinstance(raw_severity, Severity)
            else Severity(str(raw_severity).upper())
        )
        return cls(
            id=str(data["id"]),
            service=str(data["service"]).lower(),
            title=str(data.get("title", data["id"])),
            severity=severity,
            enabled=bool(data.get("enabled", True)),
            description=str(data.get("description", "")),
            remediation=str(data.get("remediation", "")),
            params=dict(data.get("params") or {}),
        )


@dataclass
class Finding:
    rule_id: str
    service: str
    resource_id: str
    region: str
    severity: Severity
    status: Status
    message: str
    remediation: str
    timestamp: str = field(default_factory=utc_now_iso)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "service": self.service,
            "resource_id": self.resource_id,
            "region": self.region,
            "severity": self.severity.value,
            "status": self.status.value,
            "message": self.message,
            "remediation": self.remediation,
            "timestamp": self.timestamp,
        }


@dataclass
class ScanResult:
    account_id: str
    scanned_regions: list[str]
    scanned_services: list[str]
    started_at: str = field(default_factory=utc_now_iso)
    finished_at: str = ""
    findings: list[Finding] = field(default_factory=list)

    def summary(self) -> dict[str, Any]:
        counts = {
            Status.PASS.value: 0,
            Status.FAIL.value: 0,
            Status.ERROR.value: 0,
        }
        fail_by_severity = {sev.value: 0 for sev in Severity}

        for finding in self.findings:
            counts[finding.status.value] += 1
            if finding.status == Status.FAIL:
                fail_by_severity[finding.severity.value] += 1

        return {
            "total": len(self.findings),
            "PASS": counts[Status.PASS.value],
            "FAIL": counts[Status.FAIL.value],
            "ERROR": counts[Status.ERROR.value],
            "fail_by_severity": fail_by_severity,
        }

    def has_failures_at_or_above(self, min_severity: Severity) -> bool:
        return any(
            f.status == Status.FAIL and f.severity.rank >= min_severity.rank
            for f in self.findings
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "account_id": self.account_id,
            "scanned_regions": self.scanned_regions,
            "scanned_services": self.scanned_services,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "summary": self.summary(),
            "findings": [f.to_dict() for f in self.findings],
        }
