from iam_to_english.analyzer import PolicyExplanation, analyze
from iam_to_english.parser import parse_policy


def test_analyze_s3_readonly(s3_readonly_policy):
    parsed = parse_policy(s3_readonly_policy)
    explanation = analyze(parsed)

    assert isinstance(explanation, PolicyExplanation)
    assert len(explanation.statements) == 1
    assert "s3" in explanation.services

    stmt = explanation.statements[0]
    assert stmt.effect == "Allow"
    assert stmt.effect_label == "ALLOW"
    assert stmt.sid == "AllowS3Read"
    assert len(stmt.actions) == 2

    # Check that descriptions are translated
    action_descs = [a.description for a in stmt.actions]
    assert any("Download" in d or "read" in d.lower() for d in action_descs)
    assert any("List" in d for d in action_descs)

    # Check resource parsing
    res_descs = [r.description for r in stmt.resources]
    assert "S3 bucket 'my-bucket'" in res_descs
    assert "all objects in S3 bucket 'my-bucket'" in res_descs

    # S3 readonly should have no high or critical warnings
    severities = {w.severity for w in explanation.warnings}
    assert "CRITICAL" not in severities
    assert "HIGH" not in severities

def test_analyze_admin_policy(admin_policy):
    parsed = parse_policy(admin_policy)
    explanation = analyze(parsed)

    assert len(explanation.statements) == 1
    # Full admin should trigger CRITICAL warning
    critical_warnings = [w for w in explanation.warnings if w.severity == "CRITICAL"]
    assert len(critical_warnings) >= 1
    assert "Full administrator access" in critical_warnings[0].message

    # Already full admin: escalation paths would be noise, the CRITICAL warning says it all
    assert explanation.escalations == []
    assert explanation.risk_level == "CRITICAL"

def test_analyze_arn_formats():
    policy = {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "lambda:InvokeFunction",
                    "dynamodb:GetItem",
                    "sqs:SendMessage",
                    "sns:Publish",
                    "kms:Decrypt"
                ],
                "Resource": [
                    "arn:aws:lambda:us-east-1:123456789012:function:my-function",
                    "arn:aws:dynamodb:us-east-1:123456789012:table/MyTable",
                    "arn:aws:sqs:us-east-1:123456789012:MyQueue",
                    "arn:aws:sns:us-east-1:123456789012:MyTopic",
                    "arn:aws:kms:us-east-1:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab"
                ]
            }
        ]
    }
    parsed = parse_policy(policy)
    explanation = analyze(parsed)
    stmt = explanation.statements[0]
    res_descs = [r.description for r in stmt.resources]

    assert any("function 'my-function' in Lambda" in d for d in res_descs)
    assert any("table 'MyTable' in DynamoDB" in d for d in res_descs)
    assert any("queue 'MyQueue' in SQS" in d for d in res_descs)
    assert any("topic 'MyTopic' in SNS" in d for d in res_descs)
    assert any("key '1234abcd-12ab-34cd-56ef-1234567890ab' in KMS" in d for d in res_descs)

def test_unknown_service_and_action_fallback():
    policy = {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "customservice:DoSpecialThing",
                "Resource": "arn:aws:customservice:us-east-1:123456789012:item/xyz"
            }
        ]
    }
    parsed = parse_policy(policy)
    explanation = analyze(parsed)
    stmt = explanation.statements[0]

    # Custom action should be given a readable name from action title
    assert "customservice:DoSpecialThing" in stmt.actions[0].raw_actions
    assert "special thing" in stmt.actions[0].description.lower()
