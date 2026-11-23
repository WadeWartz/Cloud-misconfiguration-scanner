from __future__ import annotations

import json
from pathlib import Path

from moto import mock_aws

from core.auth import create_session
from core.engine import ScanEngine, load_rules
from main import main
from reporters.html_reporter import HTMLReporter
from reporters.json_reporter import JSONReporter


@mock_aws
def test_engine_and_reporters_end_to_end(tmp_path: Path) -> None:
    session = create_session(region_name="us-east-1")
    s3 = session.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="demo-unconfigured-bucket")

    rules = load_rules("config/rules.yaml")
    engine = ScanEngine(
        session=session,
        rules=rules,
        regions=["us-east-1"],
        services=["s3", "iam", "ec2"],
    )
    result = engine.run()
    summary = result.summary()

    assert result.account_id == "123456789012"
    assert summary["total"] > 0
    assert summary["FAIL"] > 0

    json_file = tmp_path / "report.json"
    html_file = tmp_path / "report.html"

    JSONReporter().export(result, json_file)
    HTMLReporter().export(result, html_file)

    parsed_json = json.loads(json_file.read_text(encoding="utf-8"))
    assert parsed_json["account_id"] == "123456789012"
    assert len(parsed_json["findings"]) == summary["total"]

    html_text = html_file.read_text(encoding="utf-8")
    assert "Cloud Misconfiguration Scan Report" in html_text
    assert "demo-unconfigured-bucket" in html_text


@mock_aws
def test_cli_exit_code_with_fail_on(tmp_path: Path) -> None:
    out_json = tmp_path / "cli_report.json"
    # In an empty mocked AWS account, IAM-001 (CRITICAL) fails because root MFA is disabled
    exit_code_fail = main(
        [
            "--services",
            "iam",
            "--region",
            "us-east-1",
            "--format",
            "json",
            "--output",
            str(out_json),
            "--fail-on",
            "HIGH",
        ]
    )
    assert exit_code_fail == 1
    assert out_json.exists()

    # S3 with no buckets produces 0 findings -> exit code 0
    exit_code_pass = main(
        [
            "--services",
            "s3",
            "--region",
            "us-east-1",
            "--format",
            "console",
            "--fail-on",
            "LOW",
        ]
    )
    assert exit_code_pass == 0
