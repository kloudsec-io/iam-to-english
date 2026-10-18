# Security Policy

## Reporting a vulnerability

Please do not open a public issue for security problems. Email **tarek@kloudsec.io** with a description and steps to reproduce. We aim to acknowledge reports within 5 business days.

## Scope

iam-to-english reads IAM policy documents. It contacts AWS only when you give it an ARN or `--role-name` (to fetch the policy). It sends the policy to an AI provider (Amazon Bedrock, a local Ollama instance, Anthropic or OpenAI) only when you explicitly pass `--ai`. Reports about policy parsing, credential handling or unexpected network calls are in scope.

## Supported versions

Only the latest released version receives fixes.
