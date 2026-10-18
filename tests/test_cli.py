import json

from click.testing import CliRunner

from iam_to_english.cli import main


def test_cli_basic():
    runner = CliRunner()
    result = runner.invoke(main, ["examples/s3-readonly.json"])
    assert result.exit_code == 0
    assert "1 statement | Services: S3" in result.output
    assert "IN SHORT:" in result.output
    assert "Download objects from S3" in result.output

def test_cli_json_format():
    runner = CliRunner()
    result = runner.invoke(main, ["examples/s3-readonly.json", "--format", "json"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["summary"]["total_statements"] == 1
    assert "s3" in data["summary"]["services"]

def test_cli_markdown_format():
    runner = CliRunner()
    result = runner.invoke(main, ["examples/s3-readonly.json", "--format", "markdown"])
    assert result.exit_code == 0
    assert "# IAM Policy Analysis" in result.output
    assert "## ALLOW #1 (AllowS3ReadAccess)" in result.output

def test_cli_diff():
    runner = CliRunner()
    result = runner.invoke(main, ["examples/s3-readonly.json", "--diff", "examples/overly-permissive.json"])
    assert result.exit_code == 0
    assert "IAM Policy Diff:" in result.output
    assert "RISK INCREASED: CLEAN -> CRITICAL" in result.output
    assert "Permissions Added (+):" in result.output
    assert "Every action in every AWS service (*), on all resources" in result.output

def test_cli_fail_on_triggered():
    runner = CliRunner()
    # overly-permissive has CRITICAL warnings/escalations
    result = runner.invoke(main, ["examples/overly-permissive.json", "--fail-on", "HIGH"])
    assert result.exit_code == 1

def test_cli_fail_on_clean():
    runner = CliRunner()
    # s3-readonly has no CRITICAL or HIGH findings
    result = runner.invoke(main, ["examples/s3-readonly.json", "--fail-on", "HIGH"])
    assert result.exit_code == 0

def test_cli_no_color():
    runner = CliRunner()
    result = runner.invoke(main, ["examples/complex-policy.json", "--no-color"])
    assert result.exit_code == 0
    assert "\033[" not in result.output

def test_cli_no_warnings():
    runner = CliRunner()
    result = runner.invoke(main, ["examples/complex-policy.json", "--no-warnings"])
    assert result.exit_code == 0
    assert "WARNINGS:" not in result.output

def test_cli_version():
    runner = CliRunner()
    result = runner.invoke(main, ["--version"])
    assert result.exit_code == 0
    assert "iam-to-english" in result.output


def test_trust_policy_flag_accepts_role_arn_source():
    """A role ARN already means 'trust policy', so --trust-policy with it must not be a usage error."""
    from click.testing import CliRunner

    from iam_to_english.cli import main

    result = CliRunner().invoke(main, ["--trust-policy", "arn:aws:iam::123456789012:role/Missing"])
    assert "--trust-policy needs --role-name" not in result.output


def test_trust_policy_flag_without_role_is_usage_error():
    from click.testing import CliRunner

    from iam_to_english.cli import main

    result = CliRunner().invoke(main, ["--trust-policy", "examples/s3-readonly.json"])
    assert result.exit_code == 2 and "--trust-policy needs --role-name" in result.output
