from __future__ import annotations

from unittest.mock import MagicMock

import boto3
from moto import mock_aws

from core.engine import load_rules
from core.models import Status
from scanners.ec2_scanner import EC2Scanner


def _make_session() -> boto3.Session:
    return boto3.Session(
        aws_access_key_id="test",
        aws_secret_access_key="test",
        aws_session_token="test",
        region_name="us-east-1",
    )


@mock_aws
def test_ec2_scanner_security_groups_and_volumes_with_moto() -> None:
    session = _make_session()
    ec2 = session.client("ec2", region_name="us-east-1")

    # EC2-001 FAIL: Security group exposing port 22 to 0.0.0.0/0
    sg_open = ec2.create_security_group(
        GroupName="open-ssh-sg",
        Description="Open SSH to world",
    )
    sg_open_id = sg_open["GroupId"]
    ec2.authorize_security_group_ingress(
        GroupId=sg_open_id,
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }
        ],
    )

    # EC2-001 PASS: Security group exposing only 443 to 0.0.0.0/0
    sg_safe = ec2.create_security_group(
        GroupName="https-only-sg",
        Description="HTTPS only",
    )
    sg_safe_id = sg_safe["GroupId"]
    ec2.authorize_security_group_ingress(
        GroupId=sg_safe_id,
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 443,
                "ToPort": 443,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }
        ],
    )

    # EC2-002 PASS & FAIL: Encrypted vs unencrypted EBS volumes
    vol_enc = ec2.create_volume(
        AvailabilityZone="us-east-1a",
        Size=8,
        Encrypted=True,
    )
    vol_unenc = ec2.create_volume(
        AvailabilityZone="us-east-1a",
        Size=8,
        Encrypted=False,
    )

    rules = load_rules("config/rules.yaml")
    scanner = EC2Scanner(session=session, rules=rules, region="us-east-1")
    findings = scanner.scan()

    sg_findings = {
        f.resource_id: f for f in findings if f.rule_id == "EC2-001"
    }
    assert sg_findings[sg_open_id].status == Status.FAIL
    assert sg_findings[sg_safe_id].status == Status.PASS

    vol_findings = {
        f.resource_id: f for f in findings if f.rule_id == "EC2-002"
    }
    assert vol_findings[vol_enc["VolumeId"]].status == Status.PASS
    assert vol_findings[vol_unenc["VolumeId"]].status == Status.FAIL


def test_ec2_imdsv2_pass_and_fail() -> None:
    session = MagicMock()
    ec2_client = MagicMock()
    session.client.return_value = ec2_client

    empty_paginator = MagicMock()
    empty_paginator.paginate.return_value = [{}]

    instances_paginator = MagicMock()
    instances_paginator.paginate.return_value = [
        {
            "Reservations": [
                {
                    "Instances": [
                        {
                            "InstanceId": "i-imdsv2-ok",
                            "State": {"Name": "running"},
                            "MetadataOptions": {"HttpTokens": "required"},
                        },
                        {
                            "InstanceId": "i-imdsv1-allowed",
                            "State": {"Name": "running"},
                            "MetadataOptions": {"HttpTokens": "optional"},
                        },
                    ]
                }
            ]
        }
    ]

    def get_paginator(operation_name: str) -> MagicMock:
        if operation_name == "describe_instances":
            return instances_paginator
        return empty_paginator

    ec2_client.get_paginator.side_effect = get_paginator

    rules = load_rules("config/rules.yaml")
    scanner = EC2Scanner(session=session, rules=rules, region="us-east-1")
    findings = scanner.scan()

    imds_findings = {
        f.resource_id: f for f in findings if f.rule_id == "EC2-003"
    }
    assert imds_findings["i-imdsv2-ok"].status == Status.PASS
    assert imds_findings["i-imdsv1-allowed"].status == Status.FAIL

