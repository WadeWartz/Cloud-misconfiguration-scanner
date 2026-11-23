from __future__ import annotations

import json
from typing import Any

from botocore.exceptions import ClientError

from core.models import Finding, Rule, Status
from scanners.base_scanner import BaseScanner

PUBLIC_ACCESS_BLOCK_KEYS = (
    "BlockPublicAcls",
    "IgnorePublicAcls",
    "BlockPublicPolicy",
    "RestrictPublicBuckets",
)


def _is_public_principal(principal: Any) -> bool:
    if principal == "*":
        return True
    if isinstance(principal, dict):
        aws_principal = principal.get("AWS")
        if aws_principal == "*":
            return True
        if isinstance(aws_principal, list) and "*" in aws_principal:
            return True
    return False


class S3Scanner(BaseScanner):
    """Scanner for AWS S3 security misconfigurations."""

    service_name = "s3"
    is_global = True

    def scan(self) -> list[Finding]:
        if not self.rules:
            return []

        s3 = self.get_client("s3")
        try:
            response = s3.list_buckets()
            buckets = [b["Name"] for b in response.get("Buckets", [])]
        except ClientError as exc:
            return [
                self.build_error_finding(rule, "s3:list_buckets", exc)
                for rule in self.rules.values()
            ]

        findings: list[Finding] = []
        for bucket_name in buckets:
            if rule := self.get_rule("S3-001"):
                findings.append(self._check_public_access_block(s3, bucket_name, rule))
            if rule := self.get_rule("S3-002"):
                findings.append(self._check_bucket_policy(s3, bucket_name, rule))
            if rule := self.get_rule("S3-003"):
                findings.append(self._check_bucket_encryption(s3, bucket_name, rule))
            if rule := self.get_rule("S3-004"):
                findings.append(self._check_bucket_versioning(s3, bucket_name, rule))

        return findings

    def _check_public_access_block(
        self,
        s3: Any,
        bucket_name: str,
        rule: Rule,
    ) -> Finding:
        try:
            resp = s3.get_public_access_block(Bucket=bucket_name)
            config = resp.get("PublicAccessBlockConfiguration", {})
            missing = [key for key in PUBLIC_ACCESS_BLOCK_KEYS if not config.get(key, False)]
            if not missing:
                return self.build_finding(
                    rule,
                    bucket_name,
                    Status.PASS,
                    "All four S3 Block Public Access settings are enabled.",
                )
            return self.build_finding(
                rule,
                bucket_name,
                Status.FAIL,
                f"Block Public Access settings disabled or missing: {', '.join(missing)}.",
            )
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code == "NoSuchPublicAccessBlockConfiguration":
                return self.build_finding(
                    rule,
                    bucket_name,
                    Status.FAIL,
                    "No PublicAccessBlockConfiguration configured on bucket.",
                )
            return self.build_error_finding(rule, bucket_name, exc)

    def _check_bucket_policy(
        self,
        s3: Any,
        bucket_name: str,
        rule: Rule,
    ) -> Finding:
        try:
            resp = s3.get_bucket_policy(Bucket=bucket_name)
            policy_raw = resp.get("Policy", "{}")
            policy = json.loads(policy_raw) if isinstance(policy_raw, str) else policy_raw
            statements = policy.get("Statement", [])
            if isinstance(statements, dict):
                statements = [statements]

            for stmt in statements:
                if (
                    stmt.get("Effect") == "Allow"
                    and _is_public_principal(stmt.get("Principal"))
                    and not stmt.get("Condition")
                ):
                    return self.build_finding(
                        rule,
                        bucket_name,
                        Status.FAIL,
                        "Bucket policy contains an unrestricted public Allow statement.",
                    )

            return self.build_finding(
                rule,
                bucket_name,
                Status.PASS,
                "Bucket policy does not grant unrestricted public access.",
            )
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code == "NoSuchBucketPolicy":
                return self.build_finding(
                    rule,
                    bucket_name,
                    Status.PASS,
                    "No bucket policy attached.",
                )
            return self.build_error_finding(rule, bucket_name, exc)

    def _check_bucket_encryption(
        self,
        s3: Any,
        bucket_name: str,
        rule: Rule,
    ) -> Finding:
        try:
            resp = s3.get_bucket_encryption(Bucket=bucket_name)
            enc_rules = (
                resp.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
            )
            for enc_rule in enc_rules:
                default_sse = enc_rule.get("ApplyServerSideEncryptionByDefault", {})
                algo = default_sse.get("SSEAlgorithm")
                if algo:
                    return self.build_finding(
                        rule,
                        bucket_name,
                        Status.PASS,
                        f"Default encryption enabled ({algo}).",
                    )
            return self.build_finding(
                rule,
                bucket_name,
                Status.FAIL,
                "Default server-side encryption configuration has no active algorithm.",
            )
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code == "ServerSideEncryptionConfigurationNotFoundError":
                return self.build_finding(
                    rule,
                    bucket_name,
                    Status.FAIL,
                    "Default server-side encryption is not configured.",
                )
            return self.build_error_finding(rule, bucket_name, exc)

    def _check_bucket_versioning(
        self,
        s3: Any,
        bucket_name: str,
        rule: Rule,
    ) -> Finding:
        try:
            resp = s3.get_bucket_versioning(Bucket=bucket_name)
            status = resp.get("Status")
            if status == "Enabled":
                return self.build_finding(
                    rule,
                    bucket_name,
                    Status.PASS,
                    "Bucket versioning is enabled.",
                )
            return self.build_finding(
                rule,
                bucket_name,
                Status.FAIL,
                f"Bucket versioning is not enabled (current status: {status or 'Disabled'}).",
            )
        except ClientError as exc:
            return self.build_error_finding(rule, bucket_name, exc)
