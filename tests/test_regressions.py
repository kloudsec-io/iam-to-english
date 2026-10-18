"""Regression tests for bugs found while stress-testing against real-world and adversarial policies."""

import json
import urllib.parse

import pytest
from click.testing import CliRunner

from iam_to_english.analyzer import analyze
from iam_to_english.cli import main
from iam_to_english.diff import diff_policies, format_diff_json, format_diff_markdown
from iam_to_english.errors import PolicyError
from iam_to_english.escalation import detect_privilege_escalations
from iam_to_english.loader import _parse_content
from iam_to_english.parser import parse_policy


def _policy(*statements, version="2012-10-17"):
    return {"Version": version, "Statement": list(statements)}


def _analyze(*statements):
    return analyze(parse_policy(_policy(*statements)))


def _ids(explanation_or_findings):
    findings = getattr(explanation_or_findings, "escalations", explanation_or_findings)
    return {f.id for f in findings}


def _messages(explanation, severity=None):
    return [w.message for w in explanation.warnings if severity is None or w.severity == severity]


# --- Escalation engine ----------------------------------------------------------------------------


def test_notaction_that_keeps_iam_is_effectively_admin():
    exp = _analyze({"Effect": "Allow", "NotAction": "s3:*", "Resource": "*"})
    assert exp.risk_level == "CRITICAL"
    assert any("Effectively full admin" in m for m in _messages(exp, "CRITICAL"))
    assert exp.escalations == []  # no 20-path wall of text
    assert "*" in exp.services


def test_notaction_excluding_iam_still_finds_paths_and_says_why():
    exp = _analyze({"Effect": "Allow", "NotAction": ["iam:*", "organizations:*"], "Resource": "*"})
    assert "ssm-remote-execution" in _ids(exp)
    assert "attach-policy" not in _ids(exp)
    finding = next(f for f in exp.escalations if f.id == "ssm-remote-execution")
    assert finding.granted_by == ["NotAction iam:*, organizations:*"]


def test_unconditional_deny_blocks_escalation():
    findings = detect_privilege_escalations(parse_policy(_policy(
        {"Effect": "Allow", "Action": ["iam:PassRole", "ec2:RunInstances"], "Resource": "*"},
        {"Effect": "Deny", "Action": "iam:PassRole", "Resource": "*"},
    )))
    assert "passrole-ec2" not in _ids(findings)


def test_conditional_deny_does_not_block_escalation():
    findings = detect_privilege_escalations(parse_policy(_policy(
        {"Effect": "Allow", "Action": ["iam:PassRole", "ec2:RunInstances"], "Resource": "*"},
        {"Effect": "Deny", "Action": "iam:PassRole", "Resource": "*",
         "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "false"}}},
    )))
    assert "passrole-ec2" in _ids(findings)


def test_action_names_are_case_insensitive():
    exp = _analyze({"Effect": "Allow", "Action": ["IAM:attachuserpolicy"], "Resource": "*"})
    assert "attach-policy" in _ids(exp)
    assert not any("AttachUserPolicy" in m for m in _messages(exp))  # explained by the escalation path
    assert exp.services == {"iam"}
    assert exp.statements[0].actions[0].description == "Attach policies to IAM users"


def test_wildcard_action_expands_to_dangerous_actions():
    exp = _analyze({"Effect": "Allow", "Action": "iam:Put*", "Resource": "*"})
    finding = next(f for f in exp.escalations if f.id == "put-policy")
    assert finding.granted_by == ["iam:Put*"]
    assert "iam:PutUserPolicy" in finding.involved_actions
    exp = _analyze({"Effect": "Allow", "Action": "ec2:Get*", "Resource": "*"})
    assert any("ec2:Get* also grants ec2:GetPasswordData" in m for m in _messages(exp, "MEDIUM"))


def test_star_action_on_unrelated_resource_is_not_iam_escalation():
    exp = _analyze({"Effect": "Allow", "Action": "*", "Resource": "arn:aws:s3:::bucket/*"})
    assert exp.escalations == []
    assert any('"Action": "*"' in m for m in _messages(exp, "HIGH"))


def test_passed_to_service_condition_limits_vectors():
    findings = detect_privilege_escalations(parse_policy(_policy(
        {"Effect": "Allow", "Action": "iam:PassRole", "Resource": "*",
         "Condition": {"StringEquals": {"iam:PassedToService": "lambda.amazonaws.com"}}},
        {"Effect": "Allow", "Action": ["ec2:RunInstances", "lambda:CreateFunction", "lambda:InvokeFunction"],
         "Resource": "*"},
    )))
    assert "passrole-ec2" not in _ids(findings)
    assert "passrole-lambda" in _ids(findings)


def test_passrole_to_named_role_in_any_account_is_downgraded():
    findings = detect_privilege_escalations(parse_policy(_policy(
        {"Effect": "Allow", "Action": ["iam:PassRole", "ec2:RunInstances"],
         "Resource": ["arn:aws:iam::*:role/service-role/AppRole", "*"]},
    )))
    # "*" in the same statement still makes PassRole unscoped
    assert next(f for f in findings if f.id == "passrole-ec2").severity == "CRITICAL"

    findings = detect_privilege_escalations(parse_policy(_policy(
        {"Effect": "Allow", "Action": "iam:PassRole", "Resource": "arn:aws:iam::*:role/service-role/AppRole"},
        {"Effect": "Allow", "Action": "ec2:RunInstances", "Resource": "*"},
    )))
    finding = next(f for f in findings if f.id == "passrole-ec2")
    assert finding.severity == "MEDIUM"
    assert "service-role/AppRole" in finding.note


def test_self_scoped_credentials_are_not_flagged():
    exp = _analyze({"Effect": "Allow", "Action": ["iam:CreateAccessKey", "iam:UpdateLoginProfile"],
                    "Resource": "arn:aws:iam::*:user/${aws:username}"})
    assert exp.escalations == []
    assert not any("CreateAccessKey" in m or "LoginProfile" in m for m in _messages(exp))


def test_attaching_policies_to_yourself_stays_critical():
    exp = _analyze({"Effect": "Allow", "Action": "iam:AttachUserPolicy",
                    "Resource": "arn:aws:iam::*:user/${aws:username}"})
    finding = next(f for f in exp.escalations if f.id == "attach-policy")
    assert finding.severity == "CRITICAL"


def test_standalone_vector_scoped_to_specific_resources_is_downgraded():
    exp = _analyze({"Effect": "Allow", "Action": "lambda:UpdateFunctionCode",
                    "Resource": "arn:aws:lambda:eu-west-1:123456789012:function:my-fn"})
    finding = next(f for f in exp.escalations if f.id == "lambda-update-code")
    assert finding.severity == "MEDIUM"
    assert "function:my-fn" in finding.note


@pytest.mark.parametrize("action,vector", [
    ("codebuild:StartBuild", "codebuild-start-build"),
    ("iam:DeleteRolePermissionsBoundary", "permissions-boundary-removal"),
    ("ec2-instance-connect:SendSSHPublicKey", "ec2-instance-connect"),
    ("glue:UpdateDevEndpoint", "glue-update-dev-endpoint"),
])
def test_additional_vectors(action, vector):
    assert vector in _ids(_analyze({"Effect": "Allow", "Action": action, "Resource": "*"}))


def test_escalation_ignores_resource_based_statements():
    exp = _analyze({"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::111122223333:root"},
                    "Action": "iam:*", "Resource": "*"})
    assert exp.escalations == []


# --- Resource-based policies (trust, bucket) ------------------------------------------------------


def test_trust_policy_assume_role_is_not_an_identity_warning():
    exp = _analyze({"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"})
    assert exp.warnings == []
    assert exp.risk_level == "CLEAN"


def test_public_trust_policy_is_critical():
    exp = _analyze({"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "sts:AssumeRole"})
    assert any("can assume this role" in m for m in _messages(exp, "CRITICAL"))


def test_github_oidc_without_sub_condition_is_critical():
    stmt = {"Effect": "Allow",
            "Principal": {"Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"},
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": {"StringEquals": {"token.actions.githubusercontent.com:aud": "sts.amazonaws.com"}}}
    exp = _analyze(stmt)
    assert any("Any GitHub repository can assume this role" in m for m in _messages(exp, "CRITICAL"))
    assert exp.statements[0].principals == ["GitHub Actions (OIDC)"]

    stmt["Condition"]["StringLike"] = {"token.actions.githubusercontent.com:sub": "repo:my-org/my-repo:*"}
    assert _analyze(stmt).warnings == []

    stmt["Condition"]["StringLike"] = {"token.actions.githubusercontent.com:sub": "repo:*"}
    assert any("allows any repository" in m for m in _messages(_analyze(stmt), "HIGH"))


def test_aws_star_principal_is_public():
    exp = _analyze({"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "s3:PutObject",
                    "Resource": "arn:aws:s3:::b/*"})
    assert _messages(exp, "CRITICAL")


def test_public_read_is_high_not_critical():
    exp = _analyze({"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::site/*"})
    assert exp.risk_level == "HIGH"
    assert any("Anyone on the internet can download objects from S3" in m for m in _messages(exp))


def test_public_with_org_condition_is_not_flagged():
    exp = _analyze({"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*",
                    "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-abc123"}}})
    assert exp.warnings == []


# --- Plain-English output -------------------------------------------------------------------------


@pytest.mark.parametrize("arn,expected", [
    ("arn:aws:s3:::my-bucket", "S3 bucket 'my-bucket'"),
    ("arn:aws:s3:::my-bucket/*", "all objects in S3 bucket 'my-bucket'"),
    ("arn:aws:s3:::my-bucket/logs/*", "objects under 'logs/' in S3 bucket 'my-bucket'"),
    ("arn:aws:s3:::prod-*", "S3 buckets matching 'prod-*'"),
    ("arn:aws:s3:::*", "all S3 buckets"),
    ("arn:aws:states:us-east-1:123456789012:stateMachine:sm",
     "stateMachine 'sm' in Step Functions (region us-east-1, account 123456789012)"),
    ("arn:aws:logs:us-east-1:123456789012:log-group:/aws/lambda/fn:*",
     "log-group '/aws/lambda/fn' in CloudWatch Logs (region us-east-1, account 123456789012)"),
    ("arn:aws:secretsmanager:us-east-1:123456789012:secret:db-AbC",
     "secret 'db-AbC' in Secrets Manager (region us-east-1, account 123456789012)"),
    ("arn:aws:dynamodb:*:*:table/x", "table 'x' in DynamoDB (any region, any account)"),
    ("arn:aws:iam::aws:policy/AdministratorAccess", "AWS-managed policy 'AdministratorAccess'"),
    ("arn:aws:iam::123456789012:role/*", "all roles in IAM (account 123456789012)"),
])
def test_resource_descriptions(arn, expected):
    exp = _analyze({"Effect": "Allow", "Action": "s3:GetObject", "Resource": arn})
    assert exp.statements[0].resources[0].description == expected


def test_wildcard_action_description():
    exp = _analyze({"Effect": "Allow", "Action": ["ec2:Describe*", "ec2:Get*"], "Resource": "*"})
    descs = [a.description for a in exp.statements[0].actions]
    assert descs[0] == "All EC2 actions starting with 'Describe' (read-only)"
    assert "including the sensitive ec2:GetPasswordData" in descs[1]


def test_condition_phrasing():
    exp = _analyze({"Effect": "Deny", "Action": "s3:*", "Resource": "*", "Condition": {
        "Bool": {"aws:SecureTransport": False},
        "StringNotEquals": {"aws:RequestedRegion": ["eu-west-1", "eu-central-1"]},
        "IpAddress": {"aws:SourceIp": "10.0.0.0/8"},
    }})
    descs = [c.description for c in exp.statements[0].conditions]
    assert "Request does NOT use HTTPS (plain HTTP)" in descs
    assert "Requested region must not equal any of 'eu-west-1', 'eu-central-1'" in descs
    assert "Source IP must be in '10.0.0.0/8'" in descs


def test_deny_star_does_not_claim_all_services():
    exp = _analyze({"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"},
                   {"Effect": "Deny", "Action": "*", "Resource": "*",
                    "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "false"}}})
    assert exp.services == {"s3"}


def test_read_only_wildcards_do_not_trigger_mfa_warning():
    exp = _analyze({"Effect": "Allow", "Action": ["organizations:List*", "organizations:Describe*"], "Resource": "*"})
    assert exp.warnings == []


# --- Input handling -------------------------------------------------------------------------------


DOC = _policy({"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"})


@pytest.mark.parametrize("wrapped", [
    {"PolicyVersion": {"Document": DOC, "VersionId": "v1"}},          # aws iam get-policy-version
    {"Role": {"RoleName": "r", "AssumeRolePolicyDocument": DOC}},      # aws iam get-role
    {"RoleName": "r", "PolicyName": "p", "PolicyDocument": DOC},       # aws iam get-role-policy
    {"Policy": json.dumps(DOC)},                                       # aws s3api get-bucket-policy
])
def test_aws_cli_output_is_unwrapped(wrapped):
    assert _parse_content(json.dumps(wrapped), "test") == DOC


def test_url_encoded_document():
    assert _parse_content(urllib.parse.quote(json.dumps(DOC)), "test") == DOC


@pytest.mark.parametrize("doc,message", [
    ({"foo": "bar"}, "no 'Statement' key"),
    ({"Statement": ["oops"]}, "expected an object"),
    ({"Statement": [{"Effect": "Allow", "Action": [1, 2], "Resource": "*"}]}, "'Action' must be"),
    ({"Statement": [{"Effect": "Allow", "Action": "s3:*", "NotAction": "s3:Get*", "Resource": "*"}]},
     "both 'Action' and 'NotAction'"),
    ({"Statement": [{"Effect": "Allow", "Resource": "*"}]}, "missing 'Action'"),
])
def test_invalid_policies_raise_clean_errors(doc, message):
    with pytest.raises(PolicyError) as exc:
        parse_policy(doc)
    assert message in exc.value.message


# --- CLI ------------------------------------------------------------------------------------------


def _write(tmp_path, doc, name="p.json"):
    f = tmp_path / name
    f.write_text(json.dumps(doc))
    return str(f)


def test_cli_input_errors_exit_2(tmp_path):
    runner = CliRunner()
    assert runner.invoke(main, ["does-not-exist.json"]).exit_code == 2
    assert runner.invoke(main, [_write(tmp_path, {"Statement": ["x"]})]).exit_code == 2
    assert runner.invoke(main, ["--role-name", "MyRole"]).exit_code == 2


def test_cli_no_warnings_does_not_weaken_fail_on(tmp_path):
    path = _write(tmp_path, _policy({"Effect": "Allow", "Action": "s3:PutBucketPolicy", "Resource": "*"}))
    result = CliRunner().invoke(main, [path, "--no-warnings", "--fail-on", "HIGH"])
    assert "WARNINGS" not in result.output
    assert result.exit_code == 1


def test_cli_verbose_shows_attack_path():
    runner = CliRunner()
    assert "Attack path:" not in runner.invoke(main, ["examples/complex-policy.json"]).output
    assert "Attack path:" in runner.invoke(main, ["examples/complex-policy.json", "-v"]).output


def test_cli_risk_line_and_json_summary():
    runner = CliRunner()
    text = runner.invoke(main, ["examples/overly-permissive.json", "--no-color"]).output
    assert "Risk: CRITICAL" in text
    data = json.loads(runner.invoke(main, ["examples/overly-permissive.json", "-f", "json"]).output)
    assert data["summary"]["risk_level"] == "CRITICAL"


def test_cli_reads_aws_cli_output_from_stdin():
    payload = json.dumps({"PolicyVersion": {"Document": DOC}})
    result = CliRunner().invoke(main, ["-"], input=payload)
    assert result.exit_code == 0
    assert "Download objects from S3" in result.output


def test_cli_ollama_label_uses_resolved_model(monkeypatch):
    import iam_to_english.ai as ai

    monkeypatch.setattr(ai, "get_available_ollama_models", lambda url: ["gemma3:4b"])
    monkeypatch.setattr(ai, "_analyze_with_ollama", lambda policy, model, url: f"analysis by {model}")
    result = CliRunner().invoke(main, ["examples/s3-readonly.json", "--ollama", "--no-color"])
    assert result.exit_code == 0
    assert "AI Analysis (Ollama - gemma3:4b)" in result.output
    assert "analysis by gemma3:4b" in result.output


# --- Diff -----------------------------------------------------------------------------------------


def test_diff_reports_widening_per_action_and_removed_denies():
    old = parse_policy(_policy(
        {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*"},
        {"Effect": "Deny", "Action": "s3:DeleteBucket", "Resource": "*"},
    ), source_label="old")
    new = parse_policy(_policy({"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}), source_label="new")
    diff = diff_policies(old, new)

    assert diff.actions_added == []  # same action...
    assert diff.permissions_added == {"s3:GetObject": ["*"]}  # ...but now on everything
    assert diff.resources_widened == ["Download objects from S3 (s3:GetObject) now applies to all resources"]
    assert diff.denies_removed == {"s3:DeleteBucket": ["*"]}

    md = format_diff_markdown(diff)
    assert "Deny Guardrails Removed" in md
    assert "Permissions Removed" in md
    data = json.loads(format_diff_json(diff))
    assert data["denies_removed"] == {"s3:DeleteBucket": ["*"]}
    assert "resolved_warnings" in data


def test_diff_is_case_insensitive_on_actions():
    old = parse_policy(_policy({"Effect": "Allow", "Action": "s3:getobject", "Resource": "*"}))
    new = parse_policy(_policy({"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}))
    assert not diff_policies(old, new).has_changes


def test_diff_new_action_on_star_is_not_called_widened():
    old = parse_policy(_policy({"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}))
    new = parse_policy(_policy({"Effect": "Allow", "Action": ["s3:GetObject", "s3:PutObject"], "Resource": "*"}))
    diff = diff_policies(old, new)
    assert diff.permissions_added == {"s3:PutObject": ["*"]}
    assert diff.resources_widened == []


# --- Multiple sources (CI globs, pre-commit) ------------------------------------------------------


def test_cli_multiple_files_gate_and_summary():
    result = CliRunner().invoke(main, ["examples/s3-readonly.json", "examples/overly-permissive.json",
                                       "--fail-on", "HIGH"])
    assert result.exit_code == 1
    assert "=== examples/s3-readonly.json ===" in result.output
    assert "Analyzed 2 of 2 policies; 1 at or above HIGH: examples/overly-permissive.json (CRITICAL)" in result.output


def test_cli_multiple_files_json_is_a_list():
    result = CliRunner().invoke(main, ["examples/s3-readonly.json", "examples/complex-policy.json", "-f", "json"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert [d["source"] for d in data] == ["examples/s3-readonly.json", "examples/complex-policy.json"]


def test_cli_multiple_files_keeps_going_on_errors():
    result = CliRunner().invoke(main, ["examples/s3-readonly.json", "missing.json"])
    assert result.exit_code == 2
    assert "Download objects from S3" in result.output


def test_cli_multiple_sources_reject_single_source_options():
    result = CliRunner().invoke(main, ["examples/s3-readonly.json", "examples/complex-policy.json", "--ai"])
    assert result.exit_code == 2


# --- Input edge cases found in the second hardening pass ------------------------------------------


def test_yaml_unquoted_version_date_is_accepted(tmp_path):
    f = tmp_path / "p.yaml"
    f.write_text("Version: 2012-10-17\nStatement:\n  - Effect: Allow\n    Action: s3:GetObject\n    Resource: '*'\n")
    exp = analyze(parse_policy(_parse_content(f.read_text(), "p.yaml")))
    assert exp.warnings == []


def test_yaml_unquoted_wildcard_gets_a_hint():
    with pytest.raises(PolicyError) as exc:
        _parse_content("Version: '2012-10-17'\nStatement:\n  - Effect: Allow\n    Action: s3:*\n    Resource: *\n", "p")
    assert 'quote wildcards' in exc.value.message


def test_deeply_nested_json_is_a_clean_error():
    with pytest.raises(PolicyError) as exc:
        _parse_content("[" * 100000 + "]" * 100000, "deep.json")
    assert "nested too deeply" in exc.value.message


def test_utf8_bom_on_stdin():
    result = CliRunner().invoke(main, ["-"], input="\ufeff" + json.dumps(DOC))
    assert result.exit_code == 0
    assert "Download objects from S3" in result.output


def test_conflicting_source_options_are_usage_errors():
    runner = CliRunner()
    result = runner.invoke(main, ["--trust-policy"])
    assert result.exit_code == 2 and "--trust-policy needs --role-name" in result.output
    result = runner.invoke(main, ["examples/s3-readonly.json", "--s3-bucket", "b"])
    assert result.exit_code == 2 and "either --s3-bucket or a SOURCE" in result.output


def test_json_output_with_ai_stays_valid_json(monkeypatch):
    import iam_to_english.ai as ai

    monkeypatch.setattr(ai, "analyze_with_ai", lambda *a, **k: ai.AIResult(model="m1", text="looks fine"))
    result = CliRunner().invoke(main, ["examples/s3-readonly.json", "--ollama", "-f", "json"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["ai_analysis"] == {"backend": "Ollama", "model": "m1", "text": "looks fine"}

    result = CliRunner().invoke(main, ["examples/s3-readonly.json", "--ollama", "-f", "markdown"])
    assert "## AI Analysis (Ollama - `m1`)" in result.output


def test_json_output_with_failing_ai_is_still_valid_json_and_exits_2(monkeypatch):
    import iam_to_english.ai as ai

    def boom(*a, **k):
        raise PolicyError("backend down")

    monkeypatch.setattr(ai, "analyze_with_ai", boom)
    result = CliRunner().invoke(main, ["examples/s3-readonly.json", "--ai", "-f", "json"])
    assert result.exit_code == 2
    stdout = result.stdout if hasattr(result, "stdout") else result.output
    data = json.loads(stdout[stdout.index("{"):])
    assert data["ai_analysis"]["error"] == "backend down"


# --- Readability: what a human reads must be plain English ------------------------------------------


def _text(*statements, raw=False, **kw):
    import re

    from iam_to_english.formatter import format_text

    out = format_text(analyze(parse_policy(_policy(*statements), source_label="p.json")), **kw)
    out = re.sub(r"\033\[[0-9;]*m", "", out)  # colors
    return out if raw else re.sub(r"\n {6,}", " ", out)  # undo line wrapping


@pytest.mark.parametrize("statement,expected", [
    ({"Effect": "Allow", "Action": ["s3:GetObject", "s3:ListBucket"], "Resource": "arn:aws:s3:::b/*"},
     "Can download objects from S3 and list objects in an S3 bucket, on all objects in S3 bucket 'b'."),
    ({"Effect": "Allow", "Action": "*", "Resource": "*"}, "Can do anything in any AWS service, on all resources."),
    ({"Effect": "Allow", "NotAction": ["iam:*", "organizations:*"], "Resource": "*"},
     "Can do anything except IAM actions and AWS Organizations actions, on all resources."),
    ({"Effect": "Deny", "Principal": "*", "Action": "s3:*", "Resource": "arn:aws:s3:::b",
      "Condition": {"Bool": {"aws:SecureTransport": "false"}}},
     "Anyone (public access) cannot do anything in S3, on S3 bucket 'b', when request does NOT use HTTPS "
     "(plain HTTP)."),
    ({"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"},
     "The AWS service lambda.amazonaws.com can assume this role."),
    ({"Effect": "Allow", "Action": ["ec2:Describe*", "ec2:Get*"], "Resource": "*"},
     "Can use all EC2 actions starting with 'Describe' or 'Get' (including the sensitive ec2:GetPasswordData), "
     "on all resources."),
    ({"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*",
      "Condition": {"IpAddress": {"aws:SourceIp": ["10.0.0.0/8", "192.168.0.0/16"]}}},
     "Can download objects from S3, on all resources, only if source IP is in one of '10.0.0.0/8', "
     "'192.168.0.0/16'."),
    ({"Effect": "Allow", "Action": [f"lambda:{a}" for a in
                                    ("CreateFunction", "UpdateFunctionCode", "InvokeFunction", "GetFunction",
                                     "ListFunctions")], "Resource": "*"},
     "Can use 5 Lambda actions (change, run and read), on all resources."),
])
def test_statement_summaries_are_plain_sentences(statement, expected):
    assert analyze(parse_policy(_policy(statement))).statements[0].summary == expected


def test_text_output_has_in_short_block_and_names_statements_by_sid():
    out = _text({"Sid": "Deploy", "Effect": "Allow", "Action": ["lambda:CreateFunction", "lambda:InvokeFunction"],
                 "Resource": "*"},
                {"Sid": "PassAny", "Effect": "Allow", "Action": "iam:PassRole", "Resource": "*"},
                {"Sid": "Secrets", "Effect": "Allow", "Action": "secretsmanager:GetSecretValue", "Resource": "*"})
    assert "IN SHORT:\n  #1 Deploy: Can create Lambda functions and invoke Lambda functions, on all resources." in out
    assert "Found in: Statement #1 (Deploy), Statement #2 (PassAny)" in out
    assert "[MEDIUM] Statement #3 (Secrets): Can read secret values (passwords, API keys, tokens) " \
           "(secretsmanager:GetSecretValue, on all resources)" in out
    # PassRole is explained by the escalation path: no second, repeated warning
    assert "iam:PassRole, on all resources" not in out


def test_warnings_lead_with_english_not_action_names():
    exp = _analyze({"Effect": "Allow", "Action": ["s3:PutBucketPolicy", "kms:ScheduleKeyDeletion", "ssm:SendCommand",
                                                  "ec2:GetPasswordData", "iam:CreateUser"], "Resource": "*"})
    for message in _messages(exp):
        assert message[0].isupper(), message
        assert ":" not in message.split(" ", 1)[0], message  # never starts with "service:Action"


def test_text_output_wraps_to_terminal_width(monkeypatch):
    monkeypatch.setenv("COLUMNS", "70")
    out = _text({"Sid": "VeryLongStatementName", "Effect": "Allow",
                 "Action": ["s3:GetObject", "s3:PutObject", "s3:ListBucket", "s3:DeleteObject"],
                 "Resource": ["arn:aws:s3:::a-bucket/*", "arn:aws:s3:::another-bucket/*"]}, raw=True)
    long_lines = [line for line in out.splitlines() if len(line) > 70 and " " in line.strip()]
    assert long_lines == []


def test_large_policies_are_summarized_not_listed():
    actions = [f"{svc}:Get{n}" for svc in ("s3", "ec2", "iam", "kms", "sqs", "sns") for n in ("Foo", "Bar")]
    exp = _analyze({"Effect": "Allow", "Action": actions, "Resource": "*"})
    assert exp.statements[0].summary == "Can use 12 read-only actions across 6 services, on all resources."
