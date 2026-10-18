# Changelog

All notable changes to iam-to-english are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/); versioning is [SemVer](https://semver.org/).

## [1.0.0] - 2026-10-18

Initial release.

### Features
- Plain-English translation of AWS IAM policies (text, JSON, Markdown), with structural security
  warnings and a risk verdict.
- Fetch policies by file, stdin, inline JSON, policy ARN or role inline policy.
- **"In short" summary**: every report opens with one plain-English sentence per statement
  ("Anyone (public access) can download objects from S3, on all objects in S3 bucket 'site'.").
- **Anthropic API and OpenAI API backends** for the AI review (`--anthropic`, `--openai`), next to
  Ollama and Amazon Bedrock; keys are read from `ANTHROPIC_API_KEY` / `OPENAI_API_KEY`.
- **Cross-statement privilege escalation detection**: 21 known paths (PassRole + Lambda/EC2/CloudFormation/
  Glue/CodeBuild/ECS/Data Pipeline/SageMaker, policy attachment and injection, trust policy backdoor,
  policy versioning, permissions boundary tampering, access keys / login profiles, group membership,
  SSM, EC2 Instance Connect, and hijacking existing Lambda / Glue / CodeBuild resources).
- **Semantic `--diff`** between two policy versions, based on (action, resource) grants: permissions
  added/removed, actions widened to `"*"`, Deny guardrails added/removed, conditions relaxed/added,
  new/resolved warnings and escalation paths, risk level before/after.
- **`--fail-on SEVERITY`** CI gate with documented exit codes (0 ok, 1 gate reached, 2 input/usage error).
- **Multiple sources** in one run (`iam-to-english policies/*.json`) with a combined summary and exit code.
- **YAML input**, and raw AWS CLI output on stdin (`get-policy-version`, `get-role`, `get-role-policy`,
  `get-bucket-policy`, URL-encoded documents).
- Fetch **role trust policies** (`--role-name X --trust-policy` or a role ARN) and **S3 bucket policies**
  (`s3://bucket` or `--s3-bucket`).
- A **Risk verdict** line (and `summary.risk_level` in JSON) on every report.
- **Trust policy checks**: GitHub OIDC without a `sub` condition, wildcard `sub`, OIDC without conditions,
  public `sts:AssumeRole`.
- `-v/--verbose` for step-by-step attack paths; collapsible attack paths in Markdown.
- GitHub Action (`action.yml`), pre-commit hook (`.pre-commit-hooks.yaml`) and a CI workflow.
- Ollama model auto-detection when `--ai-model` is not given.
- With `-f json` / `-f markdown`, the AI review is embedded in the report (`ai_analysis`) instead of
  being printed after it, so JSON output stays valid.
