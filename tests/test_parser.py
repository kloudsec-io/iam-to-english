import click
import pytest

from iam_to_english.parser import parse_policy


def test_parse_simple_policy(s3_readonly_policy):
    parsed = parse_policy(s3_readonly_policy, source_label="test.json")
    assert parsed.version == "2012-10-17"
    assert parsed.source_label == "test.json"
    assert len(parsed.statements) == 1

    stmt = parsed.statements[0]
    assert stmt.sid == "AllowS3Read"
    assert stmt.is_allow
    assert stmt.actions == ["s3:GetObject", "s3:ListBucket"]
    assert len(stmt.resources) == 2
    assert "arn:aws:s3:::my-bucket" in stmt.resources
    assert not stmt.has_conditions
    assert stmt.get_services() == {"s3"}

def test_parse_single_statement_object():
    policy = {
        "Version": "2012-10-17",
        "Statement": {
            "Effect": "Deny",
            "Action": "s3:DeleteBucket",
            "Resource": "*"
        }
    }
    parsed = parse_policy(policy)
    assert len(parsed.statements) == 1
    stmt = parsed.statements[0]
    assert not stmt.is_allow
    assert stmt.actions == ["s3:DeleteBucket"]
    assert stmt.has_wildcard_resource

def test_parse_wildcard_admin(admin_policy):
    parsed = parse_policy(admin_policy)
    assert len(parsed.statements) == 1
    stmt = parsed.statements[0]
    assert stmt.has_wildcard_action
    assert stmt.has_wildcard_resource
    assert stmt.get_services() == {"*"}
    assert parsed.get_all_services() == {"*"}

def test_parse_conditions_and_principals():
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": ["arn:aws:iam::123456789012:root", "111122223333"]},
                "Action": "sts:AssumeRole",
                "Resource": "*",
                "Condition": {
                    "StringEquals": {
                        "aws:PrincipalTag/Department": "Engineering",
                        "aws:MultiFactorAuthPresent": True
                    },
                    "IpAddress": {
                        "aws:SourceIp": ["10.0.0.0/8"]
                    }
                }
            }
        ]
    }
    parsed = parse_policy(policy)
    stmt = parsed.statements[0]
    assert len(stmt.principals) == 2
    assert "AWS:arn:aws:iam::123456789012:root" in stmt.principals
    assert "AWS:111122223333" in stmt.principals
    assert stmt.has_conditions
    assert len(stmt.conditions) == 3

    keys = {c.key for c in stmt.conditions}
    assert "aws:PrincipalTag/Department" in keys
    assert "aws:MultiFactorAuthPresent" in keys
    assert "aws:SourceIp" in keys

def test_parse_invalid_effect():
    policy = {
        "Statement": [
            {"Effect": "Maybe", "Action": "s3:GetObject", "Resource": "*"}
        ]
    }
    with pytest.raises(click.ClickException) as excinfo:
        parse_policy(policy)
    assert "invalid Effect 'Maybe'" in str(excinfo.value)

def test_parse_invalid_statement_type():
    policy = {
        "Statement": "NotAnObjectOrList"
    }
    with pytest.raises(click.ClickException) as excinfo:
        parse_policy(policy)
    assert "'Statement' must be a list or object" in str(excinfo.value)

def test_not_action_and_not_resource():
    policy = {
        "Statement": [
            {
                "Effect": "Deny",
                "NotAction": "s3:GetObject",
                "NotResource": "arn:aws:s3:::safe-bucket/*"
            }
        ]
    }
    parsed = parse_policy(policy)
    stmt = parsed.statements[0]
    assert stmt.uses_not_action
    assert stmt.not_actions == ["s3:GetObject"]
    assert stmt.uses_not_resource
    assert stmt.not_resources == ["arn:aws:s3:::safe-bucket/*"]
