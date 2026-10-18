from __future__ import annotations

import json
import os
import re
import sys

import click

from . import __version__
from .analyzer import analyze
from .diff import diff_policies, format_diff_json, format_diff_markdown, format_diff_text
from .formatter import format_json, format_markdown, format_text
from .loader import load_policy
from .matching import SEVERITY_LEVELS
from .parser import parse_policy


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.argument("sources", nargs=-1, metavar="[SOURCE]...")
@click.option("-f", "--format", "output_format", type=click.Choice(["text", "json", "markdown"]),
              default="text", help="Output format (default: text)")
@click.option("-d", "--diff", "diff_source", default=None,
              help="Compare source against another policy (semantic diff)")
@click.option("--fail-on", type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW"], case_sensitive=False),
              default=None, help="Exit with code 1 if findings meet or exceed this severity (for CI/CD)")
@click.option("-p", "--profile", default=None, help="AWS profile (for fetching policies from AWS)")
@click.option("--role-name", default=None, help="IAM role name (for inline or trust policies)")
@click.option("--trust-policy", is_flag=True, default=False,
              help="Fetch IAM role trust policy (assume role policy)")
@click.option("--s3-bucket", default=None,
              help="Fetch policy from specified S3 bucket name")
@click.option("--ai", "use_ai", is_flag=True, default=False,
              help="Add an AI review (default backend: Amazon Bedrock)")
@click.option("--ollama", "use_ollama", is_flag=True, default=False,
              help="AI review with a local Ollama model (implies --ai)")
@click.option("--anthropic", "use_anthropic", is_flag=True, default=False,
              help="AI review with the Anthropic API, key in ANTHROPIC_API_KEY (implies --ai)")
@click.option("--openai", "use_openai", is_flag=True, default=False,
              help="AI review with the OpenAI API, key in OPENAI_API_KEY (implies --ai)")
@click.option("--ollama-url", default="http://localhost:11434",
              help="Ollama API URL (default: http://localhost:11434)")
@click.option("--ai-region", default=None,
              help="AWS region for Bedrock API calls")
@click.option("--ai-model", default=None,
              help="Model ID (Bedrock model or Ollama model name)")
@click.option("--ai-profile", default=None,
              help="AWS profile for Bedrock (if different from policy source)")
@click.option("--no-color", is_flag=True, default=False, help="Disable colored output")
@click.option("--no-warnings", is_flag=True, default=False,
              help="Hide security warnings from the output (--fail-on still evaluates them)")
@click.option("-v", "--verbose", is_flag=True, default=False,
              help="Show step-by-step attack paths for privilege escalation findings")
@click.version_option(version=__version__, prog_name="iam-to-english")
def main(
    sources,
    output_format,
    diff_source,
    fail_on,
    profile,
    role_name,
    trust_policy,
    s3_bucket,
    use_ai,
    use_ollama,
    use_anthropic,
    use_openai,
    ollama_url,
    ai_region,
    ai_model,
    ai_profile,
    no_color,
    no_warnings,
    verbose,
):
    """Translate AWS IAM policies into plain English and detect security risks.

    \b
    Examples:
      iam-to-english policy.json
      iam-to-english policy.yaml
      iam-to-english arn:aws:iam::aws:policy/ReadOnlyAccess -p myprofile
      iam-to-english --role-name MyRole --trust-policy
      iam-to-english s3://my-bucket-name
      iam-to-english old-policy.json --diff new-policy.json
      iam-to-english policy.json --fail-on HIGH
      iam-to-english policies/*.json --fail-on HIGH -f markdown
      cat policy.json | iam-to-english -
      iam-to-english policy.json --ai                  # Amazon Bedrock
      iam-to-english policy.json --ollama              # local model
      iam-to-english policy.json --anthropic           # Anthropic API
      iam-to-english policy.json --openai              # OpenAI API
      iam-to-english --role-name MyRole InlinePolicyName -p prod

    \b
    Exit codes:
      0  success (and no finding at or above --fail-on)
      1  --fail-on threshold reached
      2  invalid input, AWS/AI error, or bad usage
    """
    sources = list(sources)
    if trust_policy and not role_name and not any(":iam:" in s and ":role/" in s for s in sources):
        raise click.UsageError("--trust-policy needs --role-name (or pass the role ARN as SOURCE)")
    if s3_bucket and sources:
        raise click.UsageError("Use either --s3-bucket or a SOURCE, not both")
    if not sources:
        if s3_bucket:
            sources = [f"s3://{s3_bucket}"]
        elif role_name and trust_policy:
            sources = [role_name]
        elif role_name:
            raise click.UsageError("--role-name needs an inline policy name (SOURCE) or --trust-policy")
        elif not sys.stdin.isatty():
            sources = ["-"]
        else:
            click.echo(click.get_current_context().get_help())
            raise SystemExit(0)

    chosen = [name for name, flag in (("ollama", use_ollama), ("anthropic", use_anthropic), ("openai", use_openai))
              if flag]
    if len(chosen) > 1:
        raise click.UsageError("Choose one AI backend: --ollama, --anthropic or --openai")
    backend = chosen[0] if chosen else "bedrock"
    if chosen:
        use_ai = True
    if len(sources) > 1 and (diff_source or role_name or s3_bucket or use_ai):
        raise click.UsageError("Multiple sources cannot be combined with --diff, --role-name, --s3-bucket or --ai")
    if use_ai and diff_source:
        raise click.UsageError("--ai cannot be combined with --diff")

    # Plain output when piped, redirected, or when NO_COLOR is set (https://no-color.org)
    no_color = no_color or "NO_COLOR" in os.environ or not sys.stdout.isatty()

    def emit(output: str) -> None:
        click.echo(re.sub(r"\033\[[0-9;]*m", "", output) if no_color else output)

    threshold = SEVERITY_LEVELS[fail_on.upper()] if fail_on else None

    if diff_source:
        source = sources[0]
        old_policy_dict = load_policy(
            source, profile=profile, role_name=role_name, trust_policy=trust_policy, s3_bucket=s3_bucket
        )
        new_policy_dict = load_policy(diff_source, profile=profile)

        source_label = source if source != "-" else "original"
        diff_label = diff_source if diff_source != "-" else "modified"

        old_parsed = parse_policy(old_policy_dict, source_label=source_label)
        new_parsed = parse_policy(new_policy_dict, source_label=diff_label)

        diff_result = diff_policies(old_parsed, new_parsed)

        if output_format == "json":
            emit(format_diff_json(diff_result))
        elif output_format == "markdown":
            emit(format_diff_markdown(diff_result))
        else:
            emit(format_diff_text(diff_result))

        if threshold and SEVERITY_LEVELS.get(diff_result.new_risk_level, 0) >= threshold:
            sys.exit(1)
        return

    if len(sources) == 1:
        source = sources[0]
        policy_dict = load_policy(
            source, profile=profile, role_name=role_name, trust_policy=trust_policy, s3_bucket=s3_bucket
        )
        explanation = analyze(parse_policy(policy_dict, source_label=source if source != "-" else "stdin"))
        # Decide the CI gate before --no-warnings trims the output
        gate_failed = bool(threshold) and SEVERITY_LEVELS.get(explanation.risk_level, 0) >= threshold
        if no_warnings:
            explanation.warnings = []

        ai_args = (policy_dict, backend, ai_model, ai_region, ai_profile or profile, ollama_url)
        if output_format == "text":
            emit(format_text(explanation, verbose=verbose))
            if use_ai:
                _print_ai_text(_run_ai(*ai_args), backend, no_color)
        else:
            # Structured output stays a single valid document: the AI review is embedded in it
            ai_result, ai_error = None, None
            if use_ai:
                try:
                    ai_result = _run_ai(*ai_args)
                except click.ClickException as e:
                    ai_error = e.format_message()
                    click.echo(f"Error: {ai_error}", err=True)
            if output_format == "json":
                data = json.loads(format_json(explanation))
                if use_ai:
                    data["ai_analysis"] = (
                        {"backend": _ai_backend(backend), "model": ai_result.model, "text": ai_result.text}
                        if ai_result else {"backend": _ai_backend(backend), "error": ai_error}
                    )
                emit(json.dumps(data, indent=2))
            else:
                output = format_markdown(explanation)
                if ai_result:
                    output += f"\n## AI Analysis ({_ai_backend(backend)} - `{ai_result.model}`)\n\n{ai_result.text}\n"
                emit(output)
            if ai_error:
                sys.exit(2)

        if gate_failed:
            sys.exit(1)
        return

    # Several files (e.g. a glob in CI, or pre-commit): analyze each, keep going on errors
    results = []
    failed_sources = []
    errors = 0
    for source in sources:
        try:
            explanation = analyze(parse_policy(load_policy(source), source_label=source))
        except click.ClickException as e:
            errors += 1
            message = e.format_message()
            click.echo(f"Error: {message}" if source in message else f"Error: {source}: {message}", err=True)
            continue
        if threshold and SEVERITY_LEVELS.get(explanation.risk_level, 0) >= threshold:
            failed_sources.append(f"{source} ({explanation.risk_level})")
        if no_warnings:
            explanation.warnings = []
        results.append(explanation)

    if output_format == "json":
        emit(json.dumps([json.loads(format_json(e)) for e in results], indent=2))
    else:
        separator = "\n---\n" if output_format == "markdown" else "\n"
        rendered = []
        for e in results:
            if output_format == "markdown":
                rendered.append(format_markdown(e))
            else:
                header = f"=== {e.source_label} ==="
                rendered.append(f"{_bold(header)}\n{format_text(e, verbose=verbose)}")
        emit(separator.join(rendered))
        if output_format == "text":
            summary = f"Analyzed {len(results)} of {len(sources)} policies"
            if threshold:
                summary += f"; {len(failed_sources)} at or above {fail_on.upper()}"
                if failed_sources:
                    summary += ": " + ", ".join(failed_sources)
            emit(summary)

    if failed_sources:
        sys.exit(1)
    if errors:
        sys.exit(2)


def _bold(text: str) -> str:
    return click.style(text, bold=True)


_BACKEND_NAMES = {"bedrock": "Amazon Bedrock", "ollama": "Ollama", "anthropic": "Anthropic API",
                  "openai": "OpenAI API"}


def _ai_backend(backend: str) -> str:
    return _BACKEND_NAMES[backend]


def _run_ai(policy_dict, backend, ai_model, ai_region, ai_profile, ollama_url):
    from .ai import analyze_with_ai

    return analyze_with_ai(
        policy_dict,
        profile=ai_profile,
        region=ai_region,
        model_id=ai_model,
        backend=backend,
        ollama_url=ollama_url,
    )


def _print_ai_text(result, backend: str, no_color: bool) -> None:
    label = f"AI Analysis ({_ai_backend(backend)} - {result.model})"
    click.echo("")
    if no_color:
        click.echo(label)
        click.echo("=" * len(label))
    else:
        click.echo(click.style(label, bold=True))
        click.echo(click.style("=" * len(label), dim=True))
    click.echo("")
    click.echo(result.text)


if __name__ == "__main__":
    main()
