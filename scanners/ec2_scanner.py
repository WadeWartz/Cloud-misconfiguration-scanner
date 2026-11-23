from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError

from core.models import Finding, Rule, Status
from scanners.base_scanner import BaseScanner


def _permission_exposes_port(perm: dict[str, Any], target_ports: set[int]) -> set[int]:
    has_public_ipv4 = any(
        r.get("CidrIp") == "0.0.0.0/0" for r in perm.get("IpRanges", [])
    )
    has_public_ipv6 = any(
        r.get("CidrIpv6") == "::/0" for r in perm.get("Ipv6Ranges", [])
    )
    if not (has_public_ipv4 or has_public_ipv6):
        return set()

    protocol = str(perm.get("IpProtocol", ""))
    if protocol == "-1":
        return set(target_ports)

    from_port = perm.get("FromPort")
    to_port = perm.get("ToPort")
    if from_port is None or to_port is None:
        return set()

    return {port for port in target_ports if int(from_port) <= port <= int(to_port)}


class EC2Scanner(BaseScanner):
    """Scanner for AWS EC2 security misconfigurations."""

    service_name = "ec2"
    is_global = False

    def scan(self) -> list[Finding]:
        if not self.rules:
            return []

        ec2 = self.get_client("ec2")
        findings: list[Finding] = []

        if rule := self.get_rule("EC2-001"):
            findings.extend(self._check_security_groups(ec2, rule))
        if rule := self.get_rule("EC2-002"):
            findings.extend(self._check_ebs_encryption(ec2, rule))
        if rule := self.get_rule("EC2-003"):
            findings.extend(self._check_imdsv2(ec2, rule))

        return findings

    def _check_security_groups(self, ec2: Any, rule: Rule) -> list[Finding]:
        raw_ports = rule.params.get("sensitive_ports", [22, 3389])
        sensitive_ports = {int(p) for p in raw_ports}
        findings: list[Finding] = []

        try:
            paginator = ec2.get_paginator("describe_security_groups")
            security_groups: list[dict[str, Any]] = []
            for page in paginator.paginate():
                security_groups.extend(page.get("SecurityGroups", []))
        except ClientError as exc:
            return [self.build_error_finding(rule, "ec2:describe_security_groups", exc)]

        for sg in security_groups:
            group_id = sg.get("GroupId", "unknown")
            exposed_ports: set[int] = set()
            for perm in sg.get("IpPermissions", []):
                exposed_ports.update(_permission_exposes_port(perm, sensitive_ports))

            if exposed_ports:
                ports_str = ", ".join(str(p) for p in sorted(exposed_ports))
                findings.append(
                    self.build_finding(
                        rule,
                        group_id,
                        Status.FAIL,
                        f"Security group allows unrestricted inbound access (0.0.0.0/0 or ::/0) on sensitive port(s): {ports_str}.",
                    )
                )
            else:
                findings.append(
                    self.build_finding(
                        rule,
                        group_id,
                        Status.PASS,
                        "Security group does not expose sensitive ports to the public internet.",
                    )
                )

        return findings

    def _check_ebs_encryption(self, ec2: Any, rule: Rule) -> list[Finding]:
        findings: list[Finding] = []
        try:
            paginator = ec2.get_paginator("describe_volumes")
            volumes: list[dict[str, Any]] = []
            for page in paginator.paginate():
                volumes.extend(page.get("Volumes", []))
        except ClientError as exc:
            return [self.build_error_finding(rule, "ec2:describe_volumes", exc)]

        for volume in volumes:
            volume_id = volume.get("VolumeId", "unknown")
            if volume.get("Encrypted", False):
                findings.append(
                    self.build_finding(
                        rule,
                        volume_id,
                        Status.PASS,
                        "EBS volume is encrypted.",
                    )
                )
            else:
                findings.append(
                    self.build_finding(
                        rule,
                        volume_id,
                        Status.FAIL,
                        "EBS volume is not encrypted at rest.",
                    )
                )

        return findings

    def _check_imdsv2(self, ec2: Any, rule: Rule) -> list[Finding]:
        findings: list[Finding] = []
        try:
            paginator = ec2.get_paginator("describe_instances")
            reservations: list[dict[str, Any]] = []
            for page in paginator.paginate():
                reservations.extend(page.get("Reservations", []))
        except ClientError as exc:
            return [self.build_error_finding(rule, "ec2:describe_instances", exc)]

        for reservation in reservations:
            for instance in reservation.get("Instances", []):
                state_name = instance.get("State", {}).get("Name", "")
                if state_name == "terminated":
                    continue
                instance_id = instance.get("InstanceId", "unknown")
                http_tokens = instance.get("MetadataOptions", {}).get("HttpTokens")
                if http_tokens == "required":
                    findings.append(
                        self.build_finding(
                            rule,
                            instance_id,
                            Status.PASS,
                            "EC2 instance enforces IMDSv2 (HttpTokens=required).",
                        )
                    )
                else:
                    findings.append(
                        self.build_finding(
                            rule,
                            instance_id,
                            Status.FAIL,
                            f"EC2 instance does not enforce IMDSv2 (HttpTokens={http_tokens or 'optional'}).",
                        )
                    )

        return findings
