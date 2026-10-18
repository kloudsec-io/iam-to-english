"""Fetching policies from AWS, against moto's in-memory IAM and S3."""

import json

import boto3
import pytest
from click.testing import CliRunner
from moto import mock_aws

from iam_to_english.cli import main
from iam_to_english.errors import PolicyError
from iam_to_english.loader import load_policy

POLICY = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]}
TRUST = {"Version": "2012-10-17", "Statement": [
    {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]}


@pytest.fixture(autouse=True)
def aws(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    monkeypatch.delenv("AWS_PROFILE", raising=False)
    with mock_aws():
        yield


def _iam():
    return boto3.client("iam")


def test_customer_managed_policy_uses_default_version():
    arn = _iam().create_policy(PolicyName="p", PolicyDocument=json.dumps(POLICY))["Policy"]["Arn"]
    newer = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "iam:PassRole", "Resource": "*"}]}
    _iam().create_policy_version(PolicyArn=arn, PolicyDocument=json.dumps(newer), SetAsDefault=True)
    assert load_policy(arn) == newer


def test_aws_managed_policy(monkeypatch):
    monkeypatch.setenv("MOTO_IAM_LOAD_MANAGED_POLICIES", "true")
    with mock_aws():
        doc = load_policy("arn:aws:iam::aws:policy/ReadOnlyAccess")
    assert doc["Statement"]


def test_missing_policy():
    with pytest.raises(PolicyError) as exc:
        load_policy("arn:aws:iam::123456789012:policy/nope")
    assert "IAM policy not found" in exc.value.message


def test_role_arn_with_path_loads_trust_policy():
    _iam().create_role(RoleName="deploy", Path="/service-role/", AssumeRolePolicyDocument=json.dumps(TRUST))
    assert load_policy("arn:aws:iam::123456789012:role/service-role/deploy") == TRUST


def test_role_name_trust_policy_and_inline_policy():
    _iam().create_role(RoleName="app", AssumeRolePolicyDocument=json.dumps(TRUST))
    _iam().put_role_policy(RoleName="app", PolicyName="inline", PolicyDocument=json.dumps(POLICY))
    assert load_policy("app", role_name="app", trust_policy=True) == TRUST
    assert load_policy("inline", role_name="app") == POLICY
    with pytest.raises(PolicyError) as exc:
        load_policy("other", role_name="app")
    assert "Inline policy 'other' not found on role 'app'" in exc.value.message
    with pytest.raises(PolicyError) as exc:
        load_policy("x", role_name="ghost", trust_policy=True)
    assert "IAM role not found" in exc.value.message


def test_s3_bucket_policy():
    s3 = boto3.client("s3")
    s3.create_bucket(Bucket="with-policy")
    s3.put_bucket_policy(Bucket="with-policy", Policy=json.dumps({"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::with-policy/*"}]}))
    s3.create_bucket(Bucket="no-policy")

    assert load_policy("s3://with-policy")["Statement"][0]["Principal"] == "*"
    assert load_policy("", s3_bucket="with-policy")["Statement"][0]["Principal"] == "*"
    with pytest.raises(PolicyError) as exc:
        load_policy("s3://no-policy")
    assert "No bucket policy found" in exc.value.message
    with pytest.raises(PolicyError) as exc:
        load_policy("s3://does-not-exist")
    assert "S3 bucket not found" in exc.value.message


def test_cli_trust_policy_and_bucket_end_to_end():
    _iam().create_role(RoleName="app", AssumeRolePolicyDocument=json.dumps(TRUST))
    runner = CliRunner()
    result = runner.invoke(main, ["--role-name", "app", "--trust-policy"])
    assert result.exit_code == 0, result.output
    assert "AWS service: lambda.amazonaws.com" in result.output

    s3 = boto3.client("s3")
    s3.create_bucket(Bucket="site")
    s3.put_bucket_policy(Bucket="site", Policy=json.dumps({"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": "*", "Action": "s3:PutObject", "Resource": "arn:aws:s3:::site/*"}]}))
    result = runner.invoke(main, ["s3://site", "--fail-on", "HIGH"])
    assert result.exit_code == 1
    assert "Risk: CRITICAL" in result.output


def test_cli_missing_role_exits_2():
    result = CliRunner().invoke(main, ["arn:aws:iam::123456789012:role/ghost"])
    assert result.exit_code == 2
    assert "IAM role not found" in result.output
