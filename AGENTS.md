# AGENTS.md — Cloud Misconfiguration Scanner

> Project rules for AI coding agents. Read `SPEC.md` before implementing any module.

## 1. Project Overview
- **Goal**: Python CLI tool to scan AWS accounts for common security misconfigurations (S3, IAM, EC2) driven by YAML rules and export JSON/HTML reports.
- **Runtime**: Python 3.11+ (workspace uses Python 3.14).
- **Core Dependencies**: `boto3`, `pyyaml` (see `requirements.txt`).
- **Dev/Test Dependencies**: `pytest`, `moto[s3,iam,ec2]` (see `requirements-dev.txt`).

## 2. Architecture & Module Boundaries
Follow the structure in `README.md` and `SPEC.md`:
- `config/rules.yaml`: Declarative rule definitions (ID, service, severity, enabled, remediation, params).
- `core/models.py`: Shared dataclasses & enums (`Severity`, `Status`, `Rule`, `Finding`, `ScanResult`).
- `core/auth.py`: AWS `boto3.Session` factory (supports `--profile`, env vars, default chain, region).
- `core/engine.py`: Loads `rules.yaml`, instantiates enabled scanners, runs scans, aggregates `ScanResult`.
- `scanners/base_scanner.py`: Abstract `BaseScanner` defining the scanner interface and shared error-handling helpers.
- `scanners/{s3,iam,ec2}_scanner.py`: Service-specific scanners inheriting `BaseScanner`.
- `reporters/{json,html}_reporter.py`: Format `ScanResult` into JSON or self-contained HTML files.
- `main.py`: CLI entry point (`argparse`).
- `tests/`: `pytest` unit tests using `moto` mocks.

## 3. Coding Standards
- **Type Hints**: Required on all function signatures and class attributes (`from __future__ import annotations`).
- **Data Models**: Use standard library `dataclasses` and `enum.Enum` (avoid unnecessary heavy dependencies).
- **AWS / Boto3 Best Practices**:
  - Never hardcode AWS access keys, secrets, or account IDs.
  - Always handle `botocore.exceptions.ClientError` gracefully: if a resource or API call fails (e.g., `AccessDenied`, `NoSuchBucketPolicy`), do **not** crash the whole scan — either evaluate according to the rule or emit a `Finding` with `status=Status.ERROR`.
  - Use `boto3` paginators (`client.get_paginator(...)`) for list APIs (`list_users`, `describe_instances`, `describe_security_groups`, etc.) when available.
  - Respect `enabled: false` in `config/rules.yaml` — skip disabled rules.
- **Formatting & Simplicity**: Keep functions small and readable. Prefer standard library (`argparse`, `json`, `html`, `logging`, `datetime`) over extra third-party packages.

## 4. Testing Rules
- All unit tests **must** run offline using `moto` (or `unittest.mock`) — never make real AWS API calls in tests.
- Every rule implemented in a scanner must have at least one **PASS** test case and one **FAIL** test case.
- Run tests with `python -m pytest`.

## 5. Token-Efficient Workflow
- Work in small vertical slices (one module + its tests per turn).
- Do not rewrite unrelated files.
- Check `SPEC.md` for exact field names, rule IDs, and CLI flags before coding.
