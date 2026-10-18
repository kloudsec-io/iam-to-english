from __future__ import annotations

import json
import os
import re
import socket
import urllib.error
import urllib.request
from dataclasses import dataclass

from .errors import PolicyError

DEFAULT_BEDROCK_MODEL = "anthropic.claude-haiku-4-5-20251001-v1:0"
DEFAULT_ANTHROPIC_MODEL = "claude-opus-5-5"
DEFAULT_OPENAI_MODEL = "gpt-5"
DEFAULT_OPENAI_URL = "https://api.openai.com/v1"
API_MAX_TOKENS = 16000
API_TIMEOUT_SECONDS = 300
# Models that accept output_config.effort, and the ones that support server-side refusal fallbacks
_EFFORT_MODELS = ("claude-opus-5", "claude-fable-5", "claude-sonnet-5", "claude-haiku-5", "claude-opus-4-5",
                  "claude-opus-4-6", "claude-opus-4-7", "claude-opus-4-8", "claude-sonnet-4-6", "claude-mythos-5")
_FALLBACK_MODELS = ("claude-opus-5", "claude-fable-5-1", "claude-sonnet-5-5")
DEFAULT_OLLAMA_URL = "http://localhost:11434"
OLLAMA_PREFERRED_MODELS = ("gemma3:4b", "llama3.1:8b", "phi4:14b", "mistral:latest")
OLLAMA_FALLBACK_MODEL = "llama3.1:8b"
OLLAMA_TIMEOUT_SECONDS = 300
# Cap the answer so a small model stuck in a repetition loop cannot run until the timeout
OLLAMA_MAX_OUTPUT_TOKENS = 3072
BEDROCK_MAX_TOKENS = 8192

# Model ID namespaces used by Bedrock foundation models. Anything else before the first
# dot (us., eu., apac., global., ...) is a cross-region inference profile prefix.
_BEDROCK_PROVIDERS = {
    "ai21", "amazon", "anthropic", "cohere", "deepseek", "meta", "mistral", "openai",
    "qwen", "stability", "twelvelabs", "writer", "luma",
}

# Fallback when the inference profiles of the region cannot be listed
_REGION_GEO_PREFIXES = (
    ("ap-southeast-2", "au"),
    ("ap-southeast-4", "au"),
    ("ap-northeast-1", "jp"),
    ("ap-northeast-3", "jp"),
    ("us-gov-", "us-gov"),
    ("us-", "us"),
    ("ca-", "us"),
    ("eu-", "eu"),
    ("ap-", "apac"),
)

SYSTEM_PROMPT = """You are an AWS IAM security expert. Analyze the given IAM policy and provide:

1. A plain English summary of what the policy allows and denies
2. Security risks and potential issues
3. Privilege escalation paths if any
4. Recommendations for least-privilege improvements

Be concise, specific, and actionable. Use bullet points.
Do NOT repeat the raw JSON. Focus on what matters to a security reviewer.
Flag anything that could lead to data exposure, privilege escalation, or account compromise.
If the policy looks reasonable, say so -- don't invent problems.
"""

USER_PROMPT_TEMPLATE = """Analyze this IAM policy:

```json
{policy_json}
```

Provide your analysis in this structure:

## Summary
Brief description of what this policy is designed for.

## Permissions Breakdown
What it allows and denies, in plain English.

## Security Assessment
- Risk level: CRITICAL / HIGH / MEDIUM / LOW
- Key findings (bullet points)

## Privilege Escalation Paths
Any ways this policy could be abused to gain more permissions.

## Recommendations
Specific, actionable improvements to follow least-privilege."""


@dataclass
class AIResult:
    model: str
    text: str


def analyze_with_ai(
    policy_dict: dict,
    profile: str | None = None,
    region: str | None = None,
    model_id: str | None = None,
    backend: str = "bedrock",
    ollama_url: str = DEFAULT_OLLAMA_URL,
) -> AIResult:
    """Analyze an IAM policy with an LLM (Amazon Bedrock or a local Ollama server)."""
    user_message = USER_PROMPT_TEMPLATE.format(policy_json=json.dumps(policy_dict, indent=2))
    if backend == "ollama":
        url = _normalize_ollama_url(ollama_url)
        model = resolve_ollama_model(model_id, url)
        return AIResult(model=model, text=_analyze_with_ollama(user_message, model, url))
    if backend == "anthropic":
        return _analyze_with_anthropic(user_message, model_id or DEFAULT_ANTHROPIC_MODEL)
    if backend == "openai":
        return _analyze_with_openai(user_message, model_id or DEFAULT_OPENAI_MODEL)
    return _analyze_with_bedrock(user_message, profile, region, model_id or DEFAULT_BEDROCK_MODEL)


# --- Ollama ---------------------------------------------------------------------------------------


def _normalize_ollama_url(url: str) -> str:
    url = url.strip().rstrip("/")
    if not re.match(r"^https?://[^/\s]+", url):
        raise PolicyError(f"Invalid Ollama URL: {url!r} (expected something like http://localhost:11434)")
    return url


def get_available_ollama_models(ollama_url: str = DEFAULT_OLLAMA_URL) -> list[str]:
    """Names of the models installed in Ollama, or [] if the server cannot be reached."""
    try:
        req = urllib.request.Request(f"{ollama_url.rstrip('/')}/api/tags", headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read())
        return [m["name"] for m in data.get("models", []) if isinstance(m, dict) and m.get("name")]
    except Exception:
        return []


def resolve_ollama_model(requested_model: str | None, ollama_url: str = DEFAULT_OLLAMA_URL) -> str:
    """Use the requested model, else the best installed one, else the documented default."""
    if requested_model:
        return requested_model

    installed = get_available_ollama_models(ollama_url)
    for preferred in OLLAMA_PREFERRED_MODELS:
        if preferred in installed:
            return preferred
    for preferred in OLLAMA_PREFERRED_MODELS:
        family = preferred.split(":")[0]
        for name in installed:
            if name.split(":")[0] == family:
                return name
    return installed[0] if installed else OLLAMA_FALLBACK_MODEL


def _analyze_with_ollama(user_message: str, model_id: str, ollama_url: str) -> str:
    payload = json.dumps({
        "model": model_id,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_message},
        ],
        "stream": False,
        "options": {
            "temperature": 0.1,
            "num_predict": OLLAMA_MAX_OUTPUT_TOKENS,
            # Ollama silently drops the start of prompts longer than its context window
            "num_ctx": _ollama_context_size(SYSTEM_PROMPT + user_message),
        },
    }).encode()

    req = urllib.request.Request(
        f"{ollama_url}/api/chat",
        data=payload,
        headers={"Content-Type": "application/json"},
    )

    try:
        with urllib.request.urlopen(req, timeout=OLLAMA_TIMEOUT_SECONDS) as resp:
            raw = resp.read()
    except urllib.error.HTTPError as e:
        detail = _http_error_detail(e)
        if e.code == 404:
            raise PolicyError(
                f"Model '{model_id}' not found in Ollama{detail}.\n"
                f"Pull it first with: ollama pull {model_id}"
            ) from None
        raise PolicyError(f"Ollama returned HTTP {e.code}{detail}") from None
    except urllib.error.URLError as e:
        if isinstance(e.reason, (socket.timeout, TimeoutError)):
            raise PolicyError(_ollama_timeout_message(model_id)) from None
        raise PolicyError(
            f"Cannot reach Ollama at {ollama_url} ({e.reason}).\n"
            "Make sure Ollama is running: start it with 'ollama serve' or open the Ollama app."
        ) from None
    except (socket.timeout, TimeoutError):
        raise PolicyError(_ollama_timeout_message(model_id)) from None

    try:
        data = json.loads(raw)
        content = data["message"]["content"]
    except (ValueError, KeyError, TypeError):
        raise PolicyError("Unexpected response from Ollama (no message content). Is the URL an Ollama server?") from None
    if not isinstance(content, str) or not content.strip():
        raise PolicyError(f"Ollama model '{model_id}' returned an empty answer")
    text = content.strip()
    if data.get("done_reason") == "length":
        text += "\n\n[analysis truncated: the model reached its output limit]"
    return text


def _ollama_context_size(prompt: str) -> int:
    """Context window large enough for the prompt plus the answer (about 3 characters per token)."""
    needed = len(prompt) // 3 + OLLAMA_MAX_OUTPUT_TOKENS + 512
    size = 4096
    while size < needed and size < 65536:
        size *= 2
    return size


def _ollama_timeout_message(model_id: str) -> str:
    return (
        f"Ollama did not answer within {OLLAMA_TIMEOUT_SECONDS}s with model '{model_id}'.\n"
        "The model may be too large for this machine; try a smaller one, e.g. --ai-model gemma3:4b"
    )


def _http_error_detail(error: urllib.error.HTTPError) -> str:
    try:
        message = json.loads(error.read()).get("error")
    except Exception:
        message = None
    return f": {message}" if message else ""


# --- Amazon Bedrock -------------------------------------------------------------------------------


def _analyze_with_bedrock(user_message: str, profile: str | None, region: str | None, model_id: str) -> AIResult:
    import boto3
    from botocore.exceptions import (
        BotoCoreError,
        ClientError,
        NoCredentialsError,
        NoRegionError,
        ProfileNotFound,
    )

    try:
        session = boto3.Session(profile_name=profile, region_name=region)
    except ProfileNotFound as e:
        raise PolicyError(f"AWS profile not found: {e}") from None
    # boto3 reads AWS_DEFAULT_REGION and the profile, but not AWS_REGION, which many tools set
    region = region or session.region_name or os.environ.get("AWS_REGION", "").strip() or None
    if not region:
        raise PolicyError(
            "Amazon Bedrock needs an AWS region: pass --ai-region (e.g. --ai-region us-east-1), "
            "set AWS_REGION or AWS_DEFAULT_REGION, or set a region in your AWS profile."
        )

    try:
        runtime = session.client("bedrock-runtime", region_name=region)
    except (BotoCoreError, ValueError) as e:
        raise PolicyError(f"Cannot create the Bedrock client for region {region}: {e}") from None

    candidates = resolve_bedrock_model_candidates(model_id, region, session)
    last_error = ""
    for candidate in candidates:
        try:
            response = runtime.converse(
                modelId=candidate,
                messages=[{"role": "user", "content": [{"text": user_message}]}],
                system=[{"text": SYSTEM_PROMPT}],
                inferenceConfig={"maxTokens": BEDROCK_MAX_TOKENS, "temperature": 0.1},
            )
        except NoCredentialsError:
            raise PolicyError(
                "No AWS credentials found for Amazon Bedrock. Configure them (aws configure / aws sso login) "
                "or pass --ai-profile / -p."
            ) from None
        except NoRegionError:
            raise PolicyError("Amazon Bedrock needs an AWS region: pass --ai-region.") from None
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            message = e.response.get("Error", {}).get("Message", str(e))
            if code == "ValidationException" and _is_model_id_problem(message) and candidate != candidates[-1]:
                last_error = message
                continue  # try the next way of addressing the model
            raise PolicyError(_bedrock_error_message(code, message, candidate, region)) from None
        except BotoCoreError as e:
            raise PolicyError(f"Amazon Bedrock request failed: {e}") from None
        return AIResult(model=candidate, text=_converse_text(response, candidate))

    raise PolicyError(_bedrock_error_message("ValidationException", last_error, candidates[-1], region))


def resolve_bedrock_model_candidates(model_id: str, region: str, session=None) -> list[str]:
    """Model IDs to try, best first.

    Recent models can only be invoked on demand through a cross-region inference profile
    (e.g. 'eu.anthropic.claude-...'). The profiles available in the region are listed through
    the Bedrock API when allowed, otherwise the geography is guessed from the region name.
    """
    if model_id.startswith("arn:") or _has_profile_prefix(model_id):
        return [model_id]

    listed = _listed_profiles_for(model_id, region, session)
    if listed:
        return listed

    candidates = []
    for region_start, prefix in _REGION_GEO_PREFIXES:
        if region.startswith(region_start):
            candidates.append(f"{prefix}.{model_id}")
            break
    candidates.append(f"global.{model_id}")
    candidates.append(model_id)
    return candidates


def _has_profile_prefix(model_id: str) -> bool:
    first, dot, _ = model_id.partition(".")
    return bool(dot) and first not in _BEDROCK_PROVIDERS


def _listed_profiles_for(model_id: str, region: str, session) -> list[str]:
    """System-defined inference profiles in the region that route to this model, geo before global."""
    if session is None:
        return []
    try:
        client = session.client("bedrock", region_name=region)
        ids = []
        for page in client.get_paginator("list_inference_profiles").paginate(typeEquals="SYSTEM_DEFINED"):
            ids.extend(p.get("inferenceProfileId", "") for p in page.get("inferenceProfileSummaries", []))
    except Exception:
        return []
    matches = [i for i in ids if i.endswith("." + model_id) and _has_profile_prefix(i)]
    return sorted(matches, key=lambda i: (i.startswith("global."), i))


def _is_model_id_problem(message: str) -> bool:
    lowered = message.lower()
    return any(s in lowered for s in (
        "model identifier is invalid", "inference profile", "on-demand throughput",
        "provided model identifier", "model id", "not supported in this region",
    ))


def _bedrock_error_message(code: str, message: str, model_id: str, region: str) -> str:
    if code == "AccessDeniedException":
        return (
            f"Access denied to Bedrock model '{model_id}' in {region}: {message}\n"
            "Check that the model is enabled in the Bedrock console (Model access) and that your "
            "identity is allowed bedrock:InvokeModel on it."
        )
    if code in ("UnrecognizedClientException", "ExpiredTokenException", "InvalidSignatureException"):
        return f"AWS credentials were rejected by Bedrock ({code}): {message}"
    if code == "ResourceNotFoundException":
        return f"Bedrock model '{model_id}' was not found in {region}: {message}"
    if code == "ThrottlingException":
        return f"Bedrock throttled the request for '{model_id}'; try again in a moment. ({message})"
    if code == "ValidationException" and _is_model_id_problem(message):
        return (
            f"Bedrock cannot invoke '{model_id}' in {region}: {message}\n"
            "Pass the exact inference profile ID with --ai-model; list them with:\n"
            f"  aws bedrock list-inference-profiles --region {region}"
        )
    return f"Amazon Bedrock error ({code or 'unknown'}): {message}"


def _converse_text(response: dict, model_id: str) -> str:
    try:
        blocks = response["output"]["message"]["content"]
    except (KeyError, TypeError):
        raise PolicyError(f"Unexpected response from Bedrock model '{model_id}'") from None
    text = "\n".join(b["text"] for b in blocks if isinstance(b, dict) and isinstance(b.get("text"), str)).strip()
    if not text:
        raise PolicyError(f"Bedrock model '{model_id}' returned no text")
    if response.get("stopReason") == "max_tokens":
        text += "\n\n[analysis truncated: the model reached its output limit]"
    return text


# --- Anthropic API --------------------------------------------------------------------------------


def _analyze_with_anthropic(user_message: str, model_id: str) -> AIResult:
    try:
        import anthropic
    except ImportError:
        raise PolicyError("The Anthropic backend needs the 'anthropic' package: pip install anthropic") from None

    try:
        client = anthropic.Anthropic(timeout=API_TIMEOUT_SECONDS, max_retries=2)
    except Exception as e:
        raise PolicyError(f"Cannot create the Anthropic client: {e}") from None

    request = {
        "model": model_id,
        "max_tokens": API_MAX_TOKENS,
        "system": SYSTEM_PROMPT,
        "messages": [{"role": "user", "content": user_message}],
    }
    if model_id.startswith(_EFFORT_MODELS):
        request["output_config"] = {"effort": "high"}

    try:
        if model_id.startswith(_FALLBACK_MODELS):
            try:
                # If a safety classifier declines, the API retries on a fallback model in the same call
                response = client.beta.messages.create(
                    **request, betas=["server-side-fallback-2026-07-01"], fallbacks="default")
            except anthropic.BadRequestError as e:
                if "fallback" not in str(e).lower() and "beta" not in str(e).lower():
                    raise
                response = client.messages.create(**request)  # e.g. a gateway without the beta
        else:
            response = client.messages.create(**request)
    except anthropic.AuthenticationError:
        raise PolicyError(
            "The Anthropic API rejected the credentials. Set a valid key in ANTHROPIC_API_KEY."
        ) from None
    except anthropic.PermissionDeniedError as e:
        raise PolicyError(f"The Anthropic API key is not allowed to use '{model_id}': {_api_message(e)}") from None
    except anthropic.NotFoundError:
        raise PolicyError(f"Anthropic model '{model_id}' was not found. Check --ai-model.") from None
    except anthropic.RateLimitError as e:
        raise PolicyError(f"Anthropic API rate limit reached; try again later. ({_api_message(e)})") from None
    except anthropic.BadRequestError as e:
        raise PolicyError(f"The Anthropic API rejected the request: {_api_message(e)}") from None
    except anthropic.APITimeoutError:
        raise PolicyError(f"The Anthropic API did not answer within {API_TIMEOUT_SECONDS}s") from None
    except anthropic.APIConnectionError as e:
        raise PolicyError(f"Cannot reach the Anthropic API: {e}") from None
    except anthropic.APIStatusError as e:
        raise PolicyError(f"Anthropic API error (HTTP {e.status_code}): {_api_message(e)}") from None
    except anthropic.AnthropicError as e:
        raise PolicyError(f"Anthropic API error: {e}") from None
    except TypeError as e:
        # The SDK raises a TypeError when it finds no credentials at all
        if "authentication" not in str(e).lower():
            raise
        raise PolicyError("No Anthropic API key found: set ANTHROPIC_API_KEY.") from None

    if response.stop_reason == "refusal":
        details = getattr(response, "stop_details", None)
        category = getattr(details, "category", None)
        raise PolicyError("The model declined to analyze this policy" + (f" ({category})" if category else ""))

    text = "\n".join(b.text for b in response.content if getattr(b, "type", "") == "text").strip()
    if not text:
        raise PolicyError(f"Anthropic model '{model_id}' returned no text")
    if response.stop_reason == "max_tokens":
        text += "\n\n[analysis truncated: the model reached its output limit]"
    return AIResult(model=getattr(response, "model", None) or model_id, text=text)


def _api_message(error) -> str:
    body = getattr(error, "body", None)
    if isinstance(body, dict):
        inner = body.get("error")
        if isinstance(inner, dict) and inner.get("message"):
            return str(inner["message"])
    return str(getattr(error, "message", "") or error)


# --- OpenAI API -----------------------------------------------------------------------------------


def _analyze_with_openai(user_message: str, model_id: str) -> AIResult:
    api_key = os.environ.get("OPENAI_API_KEY", "").strip()
    if not api_key:
        raise PolicyError("The OpenAI backend needs an API key: set OPENAI_API_KEY.")
    base_url = (os.environ.get("OPENAI_BASE_URL") or DEFAULT_OPENAI_URL).strip().rstrip("/")
    if not re.match(r"^https?://[^/\s]+", base_url):
        raise PolicyError(f"Invalid OPENAI_BASE_URL: {base_url!r}")

    payload = json.dumps({
        "model": model_id,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_message},
        ],
        # Newer reasoning models reject a custom temperature and the old max_tokens parameter
        "max_completion_tokens": API_MAX_TOKENS,
    }).encode()
    req = urllib.request.Request(
        f"{base_url}/chat/completions",
        data=payload,
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {api_key}"},
    )

    try:
        with urllib.request.urlopen(req, timeout=API_TIMEOUT_SECONDS) as resp:
            raw = resp.read()
    except urllib.error.HTTPError as e:
        message = _openai_error_message(e)
        if e.code == 401:
            raise PolicyError("The OpenAI API rejected the key in OPENAI_API_KEY.") from None
        if e.code == 404:
            raise PolicyError(f"OpenAI model '{model_id}' was not found or is not available to this key "
                              f"({message}). Check --ai-model.") from None
        if e.code == 429:
            raise PolicyError(f"OpenAI rate limit or quota reached: {message}") from None
        raise PolicyError(f"OpenAI API error (HTTP {e.code}): {message}") from None
    except urllib.error.URLError as e:
        if isinstance(e.reason, (socket.timeout, TimeoutError)):
            raise PolicyError(f"The OpenAI API did not answer within {API_TIMEOUT_SECONDS}s") from None
        raise PolicyError(f"Cannot reach the OpenAI API at {base_url} ({e.reason})") from None
    except (socket.timeout, TimeoutError):
        raise PolicyError(f"The OpenAI API did not answer within {API_TIMEOUT_SECONDS}s") from None

    try:
        data = json.loads(raw)
        choice = data["choices"][0]
        content = choice["message"].get("content") or ""
    except (ValueError, KeyError, IndexError, TypeError, AttributeError):
        raise PolicyError("Unexpected response from the OpenAI API") from None
    if choice.get("finish_reason") == "content_filter":
        raise PolicyError("The OpenAI model declined to analyze this policy (content filter)")
    refusal = choice["message"].get("refusal")
    if refusal and not content.strip():
        raise PolicyError(f"The OpenAI model declined to analyze this policy: {refusal}")
    text = content.strip()
    if not text:
        raise PolicyError(f"OpenAI model '{model_id}' returned an empty answer")
    if choice.get("finish_reason") == "length":
        text += "\n\n[analysis truncated: the model reached its output limit]"
    return AIResult(model=data.get("model") or model_id, text=text)


def _openai_error_message(error: urllib.error.HTTPError) -> str:
    try:
        body = json.loads(error.read())
        return str(body.get("error", {}).get("message") or body)
    except Exception:
        return error.reason or "no details"
