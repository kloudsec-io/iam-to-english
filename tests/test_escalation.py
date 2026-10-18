from iam_to_english.escalation import detect_privilege_escalations
from iam_to_english.parser import parse_policy


def test_escalation_passrole_lambda(passrole_lambda_policy):
    parsed = parse_policy(passrole_lambda_policy)
    findings = detect_privilege_escalations(parsed)

    vector_names = [f.name for f in findings]
    assert "PassRole + Lambda Code Execution" in vector_names

    # Check finding details
    finding = next(f for f in findings if f.name == "PassRole + Lambda Code Execution")
    # PassRole is limited to one named role: still reported, but as "review that role"
    assert finding.severity == "MEDIUM"
    assert "WorkerRole" in finding.note
    assert "iam:PassRole" in finding.involved_actions
    assert "lambda:CreateFunction" in finding.involved_actions
    assert "lambda:InvokeFunction" in finding.involved_actions
    assert finding.statement_indexes == [1, 2]
    assert len(finding.attack_path) > 0
    assert len(finding.remediation) > 0

def test_escalation_passrole_ec2(passrole_ec2_policy):
    parsed = parse_policy(passrole_ec2_policy)
    findings = detect_privilege_escalations(parsed)

    vector_names = [f.name for f in findings]
    assert "PassRole + EC2 Instance Profile" in vector_names
    finding = next(f for f in findings if f.name == "PassRole + EC2 Instance Profile")
    assert finding.severity == "CRITICAL"
    assert finding.involved_actions == ["iam:PassRole", "ec2:RunInstances"]
    assert finding.note == ""

def test_escalation_false_positive_ec2_describe():
    policy = {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "iam:PassRole",
                "Resource": "*"
            },
            {
                "Effect": "Allow",
                "Action": ["ec2:DescribeInstances", "ec2:DescribeVpcs"],
                "Resource": "*"
            }
        ]
    }
    parsed = parse_policy(policy)
    findings = detect_privilege_escalations(parsed)
    vector_names = [f.name for f in findings]
    assert "PassRole + EC2 Instance Profile" not in vector_names

def test_escalation_create_access_key():
    policy = {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "iam:CreateAccessKey",
                "Resource": "*"
            }
        ]
    }
    parsed = parse_policy(policy)
    findings = detect_privilege_escalations(parsed)
    assert any("iam:CreateAccessKey" in f.name for f in findings)

def test_escalation_attach_and_put_policy():
    policy = {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "iam:AttachUserPolicy",
                    "iam:PutRolePolicy"
                ],
                "Resource": "*"
            }
        ]
    }
    parsed = parse_policy(policy)
    findings = detect_privilege_escalations(parsed)
    vector_names = [f.name for f in findings]
    assert any("Direct Policy Attachment" in n for n in vector_names)
    assert any("Inline Policy Injection" in n for n in vector_names)

def test_escalation_trust_policy_backdoor():
    policy = {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "iam:UpdateAssumeRolePolicy",
                "Resource": "*"
            }
        ]
    }
    parsed = parse_policy(policy)
    findings = detect_privilege_escalations(parsed)
    assert any("Trust Policy Backdoor" in f.name for f in findings)

def test_escalation_ssm_remote_execution():
    policy = {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "ssm:SendCommand",
                "Resource": "*"
            }
        ]
    }
    parsed = parse_policy(policy)
    findings = detect_privilege_escalations(parsed)
    assert any("Remote Command Execution via SSM" in f.name for f in findings)

def test_escalation_wildcard_iam():
    policy = {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "iam:*",
                "Resource": "*"
            }
        ]
    }
    parsed = parse_policy(policy)
    findings = detect_privilege_escalations(parsed)
    vector_names = [f.name for f in findings]
    # iam:* grants CreateAccessKey, AttachPolicy, PutPolicy, etc.
    assert any("Direct Credential Creation" in n for n in vector_names)
    assert any("Direct Policy Attachment" in n for n in vector_names)
    assert any("Inline Policy Injection" in n for n in vector_names)
    assert any("Trust Policy Backdoor" in n for n in vector_names)

def test_no_escalation_on_clean_policy(s3_readonly_policy):
    parsed = parse_policy(s3_readonly_policy)
    findings = detect_privilege_escalations(parsed)
    assert len(findings) == 0
