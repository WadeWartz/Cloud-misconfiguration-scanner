from __future__ import annotations

from datetime import datetime, timezone
import json
from typing import Any
from urllib.parse import unquote

from botocore.exceptions import ClientError

from core.models import Finding, Rule, Status
from scanners.base_scanner import BaseScanner


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _is_full_admin_document(document: Any) -> bool:
    if isinstance(document, str):
        try:
            document = json.loads(unquote(document))
        except ValueError:
            return False
    if not isinstance(document, dict):
        return False

    statements = _as_list(document.get("Statement"))
    for stmt in statements:
        if not isinstance(stmt, dict):
            continue
        if stmt.get("Effect") != "Allow":
            continue
        actions = [str(a) for a in _as_list(stmt.get("Action"))]
        resources = [str(r) for r in _as_list(stmt.get("Resource"))]
        if ("*" in actions or "*:*" in actions) and ("*" in resources):
            return True
    return False


class IAMScanner(BaseScanner):
    """Scanner for AWS IAM security misconfigurations."""

    service_name = "iam"
    is_global = True

    def scan(self) -> list[Finding]:
        if not self.rules:
            return []

        iam = self.get_client("iam")
        findings: list[Finding] = []

        if rule := self.get_rule("IAM-001"):
            findings.append(self._check_root_mfa(iam, rule))
        if rule := self.get_rule("IAM-002"):
            findings.extend(self._check_access_key_age(iam, rule))
        if rule := self.get_rule("IAM-003"):
            findings.extend(self._check_overly_permissive_policies(iam, rule))

        return findings

    def _check_root_mfa(self, iam: Any, rule: Rule) -> Finding:
        resource_id = "arn:aws:iam::root"
        try:
            resp = iam.get_account_summary()
            summary = resp.get("SummaryMap", {})
            mfa_enabled = summary.get("AccountMFAEnabled", 0)
            if mfa_enabled == 1:
                return self.build_finding(
                    rule,
                    resource_id,
                    Status.PASS,
                    "Root account MFA is enabled.",
                )
            return self.build_finding(
                rule,
                resource_id,
                Status.FAIL,
                "Root account MFA is not enabled.",
            )
        except ClientError as exc:
            return self.build_error_finding(rule, resource_id, exc)

    def _check_access_key_age(self, iam: Any, rule: Rule) -> list[Finding]:
        max_age_days = int(rule.params.get("max_key_age_days", 90))
        findings: list[Finding] = []
        now = datetime.now(timezone.utc)

        try:
            paginator = iam.get_paginator("list_users")
            users: list[dict[str, Any]] = []
            for page in paginator.paginate():
                users.extend(page.get("Users", []))
        except ClientError as exc:
            return [self.build_error_finding(rule, "iam:list_users", exc)]

        for user in users:
            user_name = user["UserName"]
            try:
                keys_resp = iam.list_access_keys(UserName=user_name)
                metadata_list = keys_resp.get("AccessKeyMetadata", [])
            except ClientError as exc:
                findings.append(self.build_error_finding(rule, user_name, exc))
                continue

            active_keys = [k for k in metadata_list if k.get("Status") == "Active"]
            if not active_keys:
                findings.append(
                    self.build_finding(
                        rule,
                        user_name,
                        Status.PASS,
                        "User has no active access keys.",
                    )
                )
                continue

            for key_meta in active_keys:
                key_id = key_meta.get("AccessKeyId", "unknown")
                create_date: datetime = key_meta["CreateDate"]
                if create_date.tzinfo is None:
                    create_date = create_date.replace(tzinfo=timezone.utc)
                age_days = (now - create_date).days
                resource_id = f"{user_name}/{key_id}"

                if age_days > max_age_days:
                    findings.append(
                        self.build_finding(
                            rule,
                            resource_id,
                            Status.FAIL,
                            f"Active access key is {age_days} days old (threshold: {max_age_days} days).",
                        )
                    )
                else:
                    findings.append(
                        self.build_finding(
                            rule,
                            resource_id,
                            Status.PASS,
                            f"Active access key age is {age_days} days (within {max_age_days}-day threshold).",
                        )
                    )

        return findings

    def _check_overly_permissive_policies(
        self,
        iam: Any,
        rule: Rule,
    ) -> list[Finding]:
        findings: list[Finding] = []
        try:
            paginator = iam.get_paginator("list_policies")
            policies: list[dict[str, Any]] = []
            for page in paginator.paginate(Scope="Local"):
                policies.extend(page.get("Policies", []))
        except ClientError as exc:
            return [self.build_error_finding(rule, "iam:list_policies", exc)]

        for policy in policies:
            policy_arn = policy.get("Arn", policy.get("PolicyName", "unknown"))
            policy_name = policy.get("PolicyName", policy_arn)
            attachment_count = int(policy.get("AttachmentCount", 0))
            default_version_id = policy.get("DefaultVersionId", "v1")

            if attachment_count <= 0:
                findings.append(
                    self.build_finding(
                        rule,
                        policy_name,
                        Status.PASS,
                        "Customer-managed policy is not attached to any principal.",
                    )
                )
                continue

            try:
                version_resp = iam.get_policy_version(
                    PolicyArn=policy_arn,
                    VersionId=default_version_id,
                )
                document = version_resp.get("PolicyVersion", {}).get("Document", {})
            except ClientError as exc:
                findings.append(self.build_error_finding(rule, policy_name, exc))
                continue

            if _is_full_admin_document(document):
                findings.append(
                    self.build_finding(
                        rule,
                        policy_name,
                        Status.FAIL,
                        "Attached customer-managed policy grants full administrative privileges (*:*).",
                    )
                )
            else:
                findings.append(
                    self.build_finding(
                        rule,
                        policy_name,
                        Status.PASS,
                        "Attached customer-managed policy does not grant wildcard (*:*) privileges.",
                    )
                )

        return findings
