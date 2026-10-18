import json

from iam_to_english.diff import diff_policies, format_diff_json, format_diff_markdown, format_diff_text
from iam_to_english.parser import parse_policy


def test_diff_identical_policies(s3_readonly_policy):
    p1 = parse_policy(s3_readonly_policy, source_label="v1.json")
    p2 = parse_policy(s3_readonly_policy, source_label="v2.json")
    diff = diff_policies(p1, p2)

    assert not diff.has_changes
    assert not diff.risk_escalated
    assert len(diff.actions_added) == 0
    assert len(diff.actions_removed) == 0

    text = format_diff_text(diff)
    assert "No semantic changes detected" in text

def test_diff_actions_and_resources():
    p1 = {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject"],
                "Resource": ["arn:aws:s3:::my-bucket/*"]
            }
        ]
    }
    p2 = {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:PutObject"],
                "Resource": ["*"]
            }
        ]
    }
    parsed1 = parse_policy(p1, source_label="old.json")
    parsed2 = parse_policy(p2, source_label="new.json")
    diff = diff_policies(parsed1, parsed2)

    assert diff.has_changes
    assert diff.actions_added == ["s3:PutObject"]
    assert diff.actions_removed == []
    assert any("now applies to all resources" in r for r in diff.resources_widened)

def test_diff_risk_escalation(s3_readonly_policy, passrole_ec2_policy):
    p1 = parse_policy(s3_readonly_policy, source_label="s3-ro")
    p2 = parse_policy(passrole_ec2_policy, source_label="admin")
    diff = diff_policies(p1, p2)

    assert diff.risk_escalated
    assert diff.old_risk_level in ("CLEAN", "LOW")
    assert diff.new_risk_level == "CRITICAL"
    assert len(diff.new_escalations) > 0

    # Markdown format check
    md = format_diff_markdown(diff)
    assert "# IAM Policy Diff: `s3-ro` -> `admin`" in md
    assert "New Privilege Escalation Paths" in md

    # JSON format check
    js_str = format_diff_json(diff)
    data = json.loads(js_str)
    assert data["old_label"] == "s3-ro"
    assert data["new_label"] == "admin"
    assert data["risk_levels"]["escalated"] is True
    assert len(data["new_escalations"]) > 0

def test_diff_conditions():
    p1 = {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "*",
                "Condition": {
                    "IpAddress": {"aws:SourceIp": ["10.0.0.0/8"]}
                }
            }
        ]
    }
    p2 = {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "*"
            }
        ]
    }
    diff = diff_policies(parse_policy(p1), parse_policy(p2))
    assert len(diff.conditions_removed) > 0
