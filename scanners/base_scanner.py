from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

import boto3
from botocore.exceptions import ClientError

from core.models import Finding, Rule, Status


class BaseScanner(ABC):
    """Abstract base scanner for AWS services."""

    service_name: str = ""
    is_global: bool = False

    def __init__(
        self,
        session: boto3.Session,
        rules: list[Rule],
        region: str | None = None,
    ) -> None:
        self.session = session
        self.region = "global" if self.is_global else (region or session.region_name or "us-east-1")
        self.rules: dict[str, Rule] = {
            rule.id: rule
            for rule in rules
            if rule.enabled and rule.service.lower() == self.service_name.lower()
        }

    def get_client(self, service: str | None = None) -> Any:
        target_service = service or self.service_name
        if self.is_global:
            region_name = self.session.region_name or "us-east-1"
            return self.session.client(target_service, region_name=region_name)
        return self.session.client(target_service, region_name=self.region)

    def get_rule(self, rule_id: str) -> Rule | None:
        return self.rules.get(rule_id)

    def build_finding(
        self,
        rule: Rule,
        resource_id: str,
        status: Status,
        message: str,
        region: str | None = None,
    ) -> Finding:
        return Finding(
            rule_id=rule.id,
            service=self.service_name,
            resource_id=resource_id,
            region=region or self.region,
            severity=rule.severity,
            status=status,
            message=message,
            remediation=rule.remediation,
        )

    def build_error_finding(
        self,
        rule: Rule,
        resource_id: str,
        error: Exception,
        region: str | None = None,
    ) -> Finding:
        if isinstance(error, ClientError):
            code = error.response.get("Error", {}).get("Code", "ClientError")
            msg = error.response.get("Error", {}).get("Message", str(error))
            error_text = f"AWS API error ({code}): {msg}"
        else:
            error_text = f"Unexpected error: {error}"
        return self.build_finding(
            rule=rule,
            resource_id=resource_id,
            status=Status.ERROR,
            message=error_text,
            region=region,
        )

    @abstractmethod
    def scan(self) -> list[Finding]:
        """Execute all enabled rules for this service and return findings."""
