from __future__ import annotations

import json
from unittest.mock import MagicMock

import boto3
from botocore.exceptions import ClientError
from moto import mock_aws

from core.engine import load_rules
from core.models import Status
from scanners.s3_scanner import S3Scanner


def _make_session() -> boto3.Session:
    return boto3.Session(
        aws_access_key_id="test",
        aws_secret_access_key="test",
        aws_session_token="test",
        region_name="us-east-1",
    )


@mock_aws
def test_s3_scanner_all_rules_pass() -> None:
    session = _make_session()
    s3 = session.client("s3", region_name="us-east-1")
    bucket = "secure-bucket"
    s3.create_bucket(Bucket=bucket)

    s3.put_public_access_block(
        Bucket=bucket,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )
    s3.put_bucket_encryption(
        Bucket=bucket,
        ServerSideEncryptionConfiguration={
            "Rules": [
                {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}
            ]
        },
    )
    s3.put_bucket_versioning(
        Bucket=bucket,
        VersioningConfiguration={"Status": "Enabled"},
    )

    rules = load_rules("config/rules.yaml")
    scanner = S3Scanner(session=session, rules=rules)
    findings = {f.rule_id: f for f in scanner.scan()}

    assert findings["S3-001"].status == Status.PASS
    assert findings["S3-002"].status == Status.PASS
    assert findings["S3-003"].status == Status.PASS
    assert findings["S3-004"].status == Status.PASS


@mock_aws
def test_s3_scanner_all_rules_fail() -> None:
    session = _make_session()
    s3 = session.client("s3", region_name="us-east-1")
    bucket = "insecure-bucket"
    s3.create_bucket(Bucket=bucket)

    # S3-001: partial public access block
    s3.put_public_access_block(
        Bucket=bucket,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": False,
            "BlockPublicPolicy": False,
            "RestrictPublicBuckets": False,
        },
    )
    # S3-002: public bucket policy
    public_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": f"arn:aws:s3:::{bucket}/*",
            }
        ],
    }
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(public_policy))

    # S3-003: remove default encryption
    s3.delete_bucket_encryption(Bucket=bucket)

    rules = load_rules("config/rules.yaml")
    scanner = S3Scanner(session=session, rules=rules)
    findings = {f.rule_id: f for f in scanner.scan()}

    assert findings["S3-001"].status == Status.FAIL
    assert findings["S3-002"].status == Status.FAIL
    assert findings["S3-003"].status == Status.FAIL
    assert findings["S3-004"].status == Status.FAIL


def test_s3_scanner_handles_list_buckets_access_denied() -> None:
    session = MagicMock()
    s3_client = MagicMock()
    s3_client.list_buckets.side_effect = ClientError(
        {"Error": {"Code": "AccessDenied", "Message": "Access Denied"}},
        "ListBuckets",
    )
    session.client.return_value = s3_client

    rules = load_rules("config/rules.yaml")
    scanner = S3Scanner(session=session, rules=rules)
    findings = scanner.scan()

    assert len(findings) == 4
    assert all(f.status == Status.ERROR for f in findings)
