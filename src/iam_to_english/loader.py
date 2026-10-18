from __future__ import annotations

import json
import sys
from urllib.parse import unquote

from .errors import PolicyError

try:
    import yaml

    HAS_YAML = True
except ImportError:  # pragma: no cover - pyyaml is a declared dependency
    HAS_YAML = False


# Wrappers produced by common AWS CLI / API calls, so their output can be piped straight in:
#   aws iam get-policy-version   -> {"PolicyVersion": {"Document": {...}}}
#   aws iam get-role             -> {"Role": {"AssumeRolePolicyDocument": {...}}}
#   aws iam get-role-policy      -> {"PolicyDocument": {...}}  (also get-user-policy / get-group-policy)
#   aws s3api get-bucket-policy  -> {"Policy": "<JSON string>"}
_WRAPPER_PATHS = (
    ("PolicyVersion", "Document"),
    ("Role", "AssumeRolePolicyDocument"),
    ("AssumeRolePolicyDocument",),
    ("PolicyDocument",),
    ("Document",),
    ("Policy",),
)


def load_policy(
    source: str,
    profile: str | None = None,
    role_name: str | None = None,
    trust_policy: bool = False,
    s3_bucket: str | None = None,
) -> dict:
    """Load an IAM policy document from various sources (file, stdin, ARN, S3, role)."""
    if s3_bucket:
        return _load_s3_bucket_policy(s3_bucket, profile)
    if source.startswith("s3://"):
        bucket = source[5:].split("/")[0]
        return _load_s3_bucket_policy(bucket, profile)
    if source == "-":
        return _load_from_stdin()
    if source.startswith("arn:") and ":iam:" in source:
        return _load_from_iam_arn(source, profile)
    stripped = source.lstrip()
    if stripped.startswith("{") or stripped.startswith(("Version:", "Statement:")):
        return _parse_content(source, "inline policy")
    if role_name:
        if trust_policy:
            return _load_role_trust_policy(role_name, profile)
        return _load_inline_policy(role_name, source, profile)
    return _load_from_file(source)


def _load_from_stdin() -> dict:
    if sys.stdin.isatty():
        raise PolicyError("No input on stdin. Pipe a policy or provide a file path.")
    return _parse_content(sys.stdin.read(), "stdin")


def _load_from_file(path: str) -> dict:
    try:
        with open(path, "r", encoding="utf-8-sig") as f:
            raw = f.read()
    except FileNotFoundError:
        raise PolicyError(f"File not found: {path}") from None
    except IsADirectoryError:
        raise PolicyError(f"Is a directory, not a file: {path}") from None
    except PermissionError:
        raise PolicyError(f"Permission denied: {path}") from None
    except UnicodeDecodeError:
        raise PolicyError(f"Not a text file (could not decode as UTF-8): {path}") from None
    return _parse_content(raw, path)


def _parse_content(raw: str, source_label: str) -> dict:
    if not raw.strip():
        raise PolicyError(f"Empty input in {source_label}: expected a JSON or YAML IAM policy")

    raw = raw.lstrip("\ufeff")
    looks_like_json = raw.lstrip().startswith(("{", "["))
    data = None
    detail = ""
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        if looks_like_json:
            detail = f" ({e})"
    except RecursionError:
        raise PolicyError(f"Invalid policy in {source_label}: the document is nested too deeply") from None

    if data is None and HAS_YAML:
        try:
            data = yaml.safe_load(raw)
        except yaml.YAMLError as e:
            if not looks_like_json:
                detail = f" (YAML: {str(e).splitlines()[0]})"
                if "alias" in str(e):
                    detail += "; in YAML, quote wildcards: Resource: \"*\""
        except RecursionError:
            raise PolicyError(f"Invalid policy in {source_label}: the document is nested too deeply") from None

    if data is None and raw.lstrip().startswith("%7B"):
        # URL-encoded documents, e.g. from CloudTrail or raw IAM API responses
        return _parse_content(unquote(raw), source_label)

    if not isinstance(data, dict):
        raise PolicyError(f"Invalid policy format in {source_label}: must be a JSON or YAML object{detail}")

    return _unwrap(data, source_label)


def _unwrap(data: dict, source_label: str) -> dict:
    """Accept raw AWS CLI output by unwrapping known envelopes around the policy document."""
    if "Statement" in data:
        return data
    for path in _WRAPPER_PATHS:
        node = data
        for key in path:
            node = node.get(key) if isinstance(node, dict) else None
        if isinstance(node, str):
            return _parse_content(node, source_label)
        if isinstance(node, dict) and "Statement" in node:
            return node
    return data


def _load_from_iam_arn(arn: str, profile: str | None = None) -> dict:
    # A role ARN means "show me who can assume this role"
    if ":role/" in arn:
        return _load_role_trust_policy(arn.rsplit("/", 1)[-1], profile)

    iam = _client("iam", profile)
    try:
        policy_info = iam.get_policy(PolicyArn=arn)
        version_id = policy_info["Policy"]["DefaultVersionId"]
        version = iam.get_policy_version(PolicyArn=arn, VersionId=version_id)
        return _as_document(version["PolicyVersion"]["Document"], arn)
    except iam.exceptions.NoSuchEntityException:
        raise PolicyError(f"IAM policy not found: {arn}") from None
    except PolicyError:
        raise
    except Exception as e:
        raise PolicyError(f"Failed to fetch IAM policy {arn}: {e}") from None


def _load_role_trust_policy(role_name: str, profile: str | None = None) -> dict:
    iam = _client("iam", profile)
    try:
        response = iam.get_role(RoleName=role_name)
        return _as_document(response["Role"]["AssumeRolePolicyDocument"], f"role {role_name}")
    except iam.exceptions.NoSuchEntityException:
        raise PolicyError(f"IAM role not found: '{role_name}'") from None
    except PolicyError:
        raise
    except Exception as e:
        raise PolicyError(f"Failed to fetch role trust policy for '{role_name}': {e}") from None


def _load_inline_policy(role_name: str, policy_name: str, profile: str | None = None) -> dict:
    iam = _client("iam", profile)
    try:
        response = iam.get_role_policy(RoleName=role_name, PolicyName=policy_name)
        return _as_document(response["PolicyDocument"], f"{role_name}/{policy_name}")
    except iam.exceptions.NoSuchEntityException:
        raise PolicyError(f"Inline policy '{policy_name}' not found on role '{role_name}'") from None
    except PolicyError:
        raise
    except Exception as e:
        raise PolicyError(f"Failed to fetch inline policy: {e}") from None


def _load_s3_bucket_policy(bucket_name: str, profile: str | None = None) -> dict:
    from botocore.exceptions import ClientError

    s3 = _client("s3", profile)
    try:
        response = s3.get_bucket_policy(Bucket=bucket_name)
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "")
        if code == "NoSuchBucketPolicy":
            raise PolicyError(f"No bucket policy found for S3 bucket: '{bucket_name}'") from None
        if code == "NoSuchBucket":
            raise PolicyError(f"S3 bucket not found: '{bucket_name}'") from None
        raise PolicyError(f"Failed to fetch bucket policy for '{bucket_name}': {e}") from None
    except Exception as e:
        raise PolicyError(f"Failed to fetch bucket policy for '{bucket_name}': {e}") from None
    return _parse_content(response["Policy"], f"s3://{bucket_name}")


def _as_document(document, source_label: str) -> dict:
    # boto3 normally decodes IAM documents into dicts; handle raw (URL-encoded) strings too
    if isinstance(document, str):
        return _parse_content(document, source_label)
    return document


def _client(service: str, profile: str | None):
    import boto3

    try:
        return boto3.Session(profile_name=profile).client(service)
    except Exception as e:
        raise PolicyError(f"Cannot create AWS {service} client: {e}") from None
