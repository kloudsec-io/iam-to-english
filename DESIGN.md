# iam-to-english - Design Document

## What it does

CLI tool that parses AWS IAM policies (identity, trust, bucket and other resource-based policies) and
explains in plain English what each statement allows, who it applies to, and what could go wrong:
cross-statement privilege escalation paths, public access, wildcard abuse and risky trust relationships.
Two analysis modes: offline (deterministic, free, always on) and AI (Bedrock, Ollama, Anthropic or OpenAI, opt-in).

## Design Principles

1. `iam-to-english policy.json` should just work, including raw AWS CLI output piped on stdin
2. Offline mode is deterministic, not probabilistic, and never touches the network
3. Precision over recall: a finding people learn to ignore is worse than no finding
4. Every finding explains the risk and the fix
5. CI-friendly: stable exit codes, JSON/Markdown output, a gate (`--fail-on`) and a semantic diff

## Architecture

```
CLI (Click)
  Loader -> Parser -> Analyzer ----------> Formatter (text / json / markdown)
                        |  \
                        |   Escalation engine (cross-statement vectors)
                        |
                      Matching (case-insensitive actions, coarse allow/deny evaluation)

  Diff: Parser x2 -> grants (action x resource) + Analyzer x2 -> diff formatter
  AI (opt-in): Ollama (local), Amazon Bedrock, Anthropic API or OpenAI API
```

## Evaluation model

The engine answers "could this identity policy allow action X?" without the request context, so it is
deliberately conservative:

| Element | Treatment |
|---|---|
| `Action` / `NotAction` | Matched case-insensitively with `*` and `?` wildcards |
| `Resource` | Must plausibly belong to the action's service (`"*"`, a matching ARN service, or `NotResource`) |
| `Deny` | Removes an action only when unconditional and on `"*"` |
| `Condition` | Translated to English; `iam:PassedToService` is enforced for PassRole vectors; restricting keys (org ID, source ARN, ...) suppress public-access warnings |
| `Principal` | Statements with a Principal are resource-based: they get trust/public checks, not escalation checks |
| Scoping | PassRole to named roles -> MEDIUM ("review that role"); other vectors limited to specific resources -> one level lower; `${aws:username}` self-service is safe for credentials, not for attaching policies |

## Input Sources

| Source | Example |
|--------|---------|
| File (JSON/YAML), several at once | `iam-to-english policies/*.json` |
| Stdin (incl. raw AWS CLI output) | `aws iam get-role --role-name r \| iam-to-english -` |
| Inline JSON/YAML | `iam-to-english '{"Version":"2012-10-17",...}'` |
| AWS managed/customer policy | `iam-to-english arn:aws:iam::aws:policy/ReadOnlyAccess -p myprofile` |
| Role trust policy | `iam-to-english arn:aws:iam::123456789012:role/deploy` or `--role-name r --trust-policy` |
| Role inline policy | `iam-to-english --role-name MyRole InlinePolicyName -p prod` |
| S3 bucket policy | `iam-to-english s3://my-bucket` |

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success, no finding at or above `--fail-on` |
| 1 | `--fail-on` threshold reached |
| 2 | Invalid input, AWS/AI error, or bad usage |

## Tech Stack

- Python 3.10+
- Click -- CLI framework
- PyYAML -- YAML input
- boto3 >= 1.35 -- AWS API calls (fetching policies, Bedrock `converse`)
- anthropic >= 1.0 -- Anthropic API backend (the OpenAI and Ollama backends use the standard library)

## Package Structure

```
iam-to-english/
  pyproject.toml, Dockerfile, action.yml, .pre-commit-hooks.yaml
  README.md, DESIGN.md, CHANGELOG.md, CONTRIBUTING.md, SECURITY.md, LICENSE
  examples/   -- sample policies (identity, trust, bucket, YAML)
  tests/      -- pytest suite
  src/iam_to_english/
    cli.py, loader.py, parser.py, matching.py, analyzer.py,
    escalation.py, diff.py, formatter.py, catalog.py, ai.py, errors.py
```

## Future Ideas

- Combine several policies into one effective identity (user + groups + boundary + SCP)
- `--simulate ACTION RESOURCE`: explain whether a specific request would be allowed and why
- `--suggest`: generate a least-privilege rewrite
- SARIF output for GitHub code scanning
- Terraform / CloudFormation input (extract inline policy documents)
