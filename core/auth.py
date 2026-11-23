from __future__ import annotations

import boto3
from botocore.exceptions import BotoCoreError, ClientError


def create_session(
    profile_name: str | None = None,
    region_name: str | None = None,
) -> boto3.Session:
    """Create a boto3 Session using profile, region, or the default credential chain."""
    kwargs: dict[str, str] = {}
    if profile_name:
        kwargs["profile_name"] = profile_name
    if region_name:
        kwargs["region_name"] = region_name
    return boto3.Session(**kwargs)


def resolve_region(
    session: boto3.Session,
    region_name: str | None = None,
) -> str:
    """Resolve the target AWS region from explicit input, session config, or fallback."""
    if region_name:
        return region_name
    if session.region_name:
        return session.region_name
    return "us-east-1"


def get_account_id(session: boto3.Session) -> str:
    """Retrieve the AWS Account ID via STS, returning 'unknown' on failure."""
    try:
        sts = session.client("sts")
        identity = sts.get_caller_identity()
        return str(identity.get("Account", "unknown"))
    except (ClientError, BotoCoreError, Exception):
        return "unknown"
