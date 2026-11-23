from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from unittest.mock import MagicMock

import boto3
from moto import mock_aws

from core.engine import load_rules
from core.models import Status
from scanners.iam_scanner import IAMScanner


def _make_session() -> boto3.Session:
    return boto3.Session(
        aws_access_key_id="test",
        aws_secret_access_key="test",
        aws_session_token="test",
        region_name="us-east-1",
    )


@mock_aws
def test_iam_scanner_pass_and_fail_with_moto() -> None:
    session = _make_session()
    iam = session.client("iam", region_name="us-east-1")

    # Create user with fresh access key (PASS for IAM-002)
    iam.create_user(UserName="alice")
    iam.create_access_key(UserName="alice")

    # Create user with no access keys (PASS for IAM-002)
    iam.create_user(UserName="bob")

    # Create scoped policy and attach to alice (PASS for IAM-003)
    scoped_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject"],
                "Resource": ["arn:aws:s3:::example-bucket/*"],
            }
        ],
    }
    scoped_resp = iam.create_policy(
        PolicyName="ScopedS3Read",
        PolicyDocument=json.dumps(scoped_doc),
    )
    iam.attach_user_policy(
        UserName="alice",
        PolicyArn=scoped_resp["Policy"]["Arn"],
    )

    # Create full-admin policy and attach to bob (FAIL for IAM-003)
    admin_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*",
            }
        ],
    }
    admin_resp = iam.create_policy(
        PolicyName="FullAdminCustom",
        PolicyDocument=json.dumps(admin_doc),
    )
    iam.attach_user_policy(
        UserName="bob",
        PolicyArn=admin_resp["Policy"]["Arn"],
    )

    rules = load_rules("config/rules.yaml")
    scanner = IAMScanner(session=session, rules=rules)
    findings = scanner.scan()

    # IAM-001: moto defaults AccountMFAEnabled to 0 -> FAIL
    iam_001 = [f for f in findings if f.rule_id == "IAM-001"]
    assert len(iam_001) == 1
    assert iam_001[0].status == Status.FAIL

    # IAM-002: both alice (fresh key) and bob (no key) PASS
    iam_002 = [f for f in findings if f.rule_id == "IAM-002"]
    assert len(iam_002) == 2
    assert all(f.status == Status.PASS for f in iam_002)

    # IAM-003: ScopedS3Read PASS, FullAdminCustom FAIL
    iam_003 = {f.resource_id: f for f in findings if f.rule_id == "IAM-003"}
    assert iam_003["ScopedS3Read"].status == Status.PASS
    assert iam_003["FullAdminCustom"].status == Status.FAIL


def test_iam_root_mfa_pass_and_old_key_fail() -> None:
    session = MagicMock()
    iam_client = MagicMock()
    session.client.return_value = iam_client

    # IAM-001 PASS: AccountMFAEnabled == 1
    iam_client.get_account_summary.return_value = {
        "SummaryMap": {"AccountMFAEnabled": 1}
    }

    # IAM-002 FAIL: active key created 120 days ago
    old_date = datetime.now(timezone.utc) - timedelta(days=120)
    user_paginator = MagicMock()
    user_paginator.paginate.return_value = [{"Users": [{"UserName": "legacy-user"}]}]

    policy_paginator = MagicMock()
    policy_paginator.paginate.return_value = [{"Policies": []}]

    def get_paginator(operation_name: str) -> MagicMock:
        if operation_name == "list_users":
            return user_paginator
        return policy_paginator

    iam_client.get_paginator.side_effect = get_paginator
    iam_client.list_access_keys.return_value = {
        "AccessKeyMetadata": [
            {
                "UserName": "legacy-user",
                "AccessKeyId": "AKIAOLDKEY123456",
                "Status": "Active",
                "CreateDate": old_date,
            }
        ]
    }

    rules = load_rules("config/rules.yaml")
    scanner = IAMScanner(session=session, rules=rules)
    findings = scanner.scan()

    iam_001 = next(f for f in findings if f.rule_id == "IAM-001")
    iam_002 = next(f for f in findings if f.rule_id == "IAM-002")

    assert iam_001.status == Status.PASS
    assert iam_002.status == Status.FAIL
    assert "120 days old" in iam_002.message
