"""Anthropic and OpenAI backends against a local HTTP server (the real SDK / HTTP code runs end to end)."""

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from click.testing import CliRunner

import iam_to_english.ai as ai
from iam_to_english.cli import main
from iam_to_english.errors import PolicyError

POLICY = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]}


class FakeAPI:
    """Records requests and answers with a queued (status, body) per POST."""

    def __init__(self):
        self.requests = []
        self.responses = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                length = int(self.headers.get("Content-Length", 0))
                body = json.loads(self.rfile.read(length) or b"{}")
                outer.requests.append({"path": self.path, "headers": {k.lower(): v for k, v in self.headers.items()},
                                       "body": body})
                status, payload = outer.responses.pop(0) if outer.responses else (500, {"error": "no response"})
                data = json.dumps(payload).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def api():
    server = FakeAPI()
    yield server
    server.close()


# --- Anthropic ------------------------------------------------------------------------------------


def _message(text="looks fine", stop="end_turn", model="claude-opus-5-5"):
    return {
        "id": "msg_1", "type": "message", "role": "assistant", "model": model,
        "content": [{"type": "thinking", "thinking": "", "signature": "sig"}, {"type": "text", "text": text}],
        "stop_reason": stop, "stop_sequence": None,
        "usage": {"input_tokens": 10, "output_tokens": 5},
    }


def _error(kind, message):
    return {"type": "error", "error": {"type": kind, "message": message}}


@pytest.fixture
def anthropic_env(api, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_BASE_URL", api.url)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    monkeypatch.delenv("ANTHROPIC_AUTH_TOKEN", raising=False)
    return api


def test_anthropic_default_model_request_shape(anthropic_env):
    anthropic_env.responses.append((200, _message("review text")))
    result = ai.analyze_with_ai(POLICY, backend="anthropic")
    assert (result.model, result.text) == ("claude-opus-5-5", "review text")  # thinking block ignored

    request = anthropic_env.requests[-1]
    assert request["path"].startswith("/v1/messages")
    assert request["headers"]["x-api-key"] == "test-key"
    assert "server-side-fallback-2026-07-01" in request["headers"].get("anthropic-beta", "")
    body = request["body"]
    assert body["model"] == "claude-opus-5-5"
    assert body["fallbacks"] == "default"
    assert body["output_config"] == {"effort": "high"}
    assert body["max_tokens"] == ai.API_MAX_TOKENS
    assert '"s3:GetObject"' in body["messages"][0]["content"]
    assert "IAM security expert" in body["system"]


def test_anthropic_older_model_gets_no_effort_or_fallbacks(anthropic_env):
    anthropic_env.responses.append((200, _message(model="claude-haiku-4-5")))
    ai.analyze_with_ai(POLICY, backend="anthropic", model_id="claude-haiku-4-5")
    body = anthropic_env.requests[-1]["body"]
    assert "fallbacks" not in body and "output_config" not in body


def test_anthropic_retries_without_fallbacks_when_gateway_rejects_them(anthropic_env):
    anthropic_env.responses += [(400, _error("invalid_request_error", "fallbacks: unknown beta")),
                                (200, _message("ok"))]
    assert ai.analyze_with_ai(POLICY, backend="anthropic").text == "ok"
    assert "fallbacks" not in anthropic_env.requests[-1]["body"]


def test_anthropic_served_by_fallback_model_is_reported(anthropic_env):
    anthropic_env.responses.append((200, _message("ok", model="claude-opus-4-8")))
    assert ai.analyze_with_ai(POLICY, backend="anthropic").model == "claude-opus-4-8"


@pytest.mark.parametrize("status,kind,expected", [
    (401, "authentication_error", "rejected the credentials"),
    (403, "permission_error", "not allowed to use"),
    (404, "not_found_error", "was not found"),
    (400, "invalid_request_error", "rejected the request: prompt is too long"),
])
def test_anthropic_errors(anthropic_env, status, kind, expected):
    anthropic_env.responses.append((status, _error(kind, "prompt is too long")))
    with pytest.raises(PolicyError) as exc:
        ai.analyze_with_ai(POLICY, backend="anthropic", model_id="claude-haiku-4-5")
    assert expected in exc.value.message


def test_anthropic_refusal_and_truncation(anthropic_env):
    refusal = _message("", stop="refusal")
    refusal["content"] = []
    refusal["stop_details"] = {"type": "refusal", "category": "cyber", "explanation": None}
    anthropic_env.responses.append((200, refusal))
    with pytest.raises(PolicyError) as exc:
        ai.analyze_with_ai(POLICY, backend="anthropic", model_id="claude-haiku-4-5")
    assert "declined" in exc.value.message and "cyber" in exc.value.message

    anthropic_env.responses.append((200, _message("partial", stop="max_tokens")))
    assert "truncated" in ai.analyze_with_ai(POLICY, backend="anthropic", model_id="claude-haiku-4-5").text


def test_anthropic_without_credentials(monkeypatch, tmp_path, api):
    monkeypatch.setenv("ANTHROPIC_BASE_URL", api.url)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_AUTH_TOKEN", raising=False)
    monkeypatch.delenv("ANTHROPIC_PROFILE", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    with pytest.raises(PolicyError) as exc:
        ai.analyze_with_ai(POLICY, backend="anthropic")
    assert "ANTHROPIC_API_KEY" in exc.value.message


def test_cli_anthropic_end_to_end(anthropic_env):
    anthropic_env.responses.append((200, _message("Deep review.")))
    result = CliRunner().invoke(main, ["examples/s3-readonly.json", "--anthropic"])
    assert result.exit_code == 0, result.output
    assert "AI Analysis (Anthropic API - claude-opus-5-5)" in result.output
    assert result.output.rstrip().endswith("Deep review.")


# --- OpenAI ---------------------------------------------------------------------------------------


@pytest.fixture
def openai_env(api, monkeypatch):
    monkeypatch.setenv("OPENAI_BASE_URL", api.url + "/v1/")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    return api


def _completion(text="openai review", finish="stop", model="gpt-5", refusal=None):
    return {"id": "c1", "object": "chat.completion", "model": model,
            "choices": [{"index": 0, "finish_reason": finish,
                         "message": {"role": "assistant", "content": text, "refusal": refusal}}]}


def test_openai_request_shape(openai_env):
    openai_env.responses.append((200, _completion()))
    result = ai.analyze_with_ai(POLICY, backend="openai")
    assert (result.model, result.text) == ("gpt-5", "openai review")
    request = openai_env.requests[-1]
    assert request["path"] == "/v1/chat/completions"
    assert request["headers"]["authorization"] == "Bearer sk-test"
    body = request["body"]
    assert body["model"] == ai.DEFAULT_OPENAI_MODEL
    assert body["max_completion_tokens"] == ai.API_MAX_TOKENS
    assert "temperature" not in body and "max_tokens" not in body
    assert [m["role"] for m in body["messages"]] == ["system", "user"]


@pytest.mark.parametrize("status,payload,expected", [
    (401, {"error": {"message": "Incorrect API key"}}, "rejected the key"),
    (404, {"error": {"message": "The model `gpt-x` does not exist"}}, "was not found"),
    (429, {"error": {"message": "You exceeded your current quota"}}, "quota"),
    (500, {"error": {"message": "server error"}}, "(HTTP 500): server error"),
    (200, {"unexpected": True}, "Unexpected response"),
    (200, _completion("", refusal="I can't help with that"), "declined"),
    (200, _completion("", finish="content_filter"), "content filter"),
])
def test_openai_errors(openai_env, status, payload, expected):
    openai_env.responses.append((status, payload))
    with pytest.raises(PolicyError) as exc:
        ai.analyze_with_ai(POLICY, backend="openai", model_id="gpt-x")
    assert expected in exc.value.message


def test_openai_truncation_and_missing_key(openai_env, monkeypatch):
    openai_env.responses.append((200, _completion("partial", finish="length")))
    assert "truncated" in ai.analyze_with_ai(POLICY, backend="openai").text
    monkeypatch.delenv("OPENAI_API_KEY")
    with pytest.raises(PolicyError) as exc:
        ai.analyze_with_ai(POLICY, backend="openai")
    assert "OPENAI_API_KEY" in exc.value.message


def test_cli_openai_end_to_end_json(openai_env):
    openai_env.responses.append((200, _completion("JSON review", model="gpt-5-2026-08-01")))
    result = CliRunner().invoke(main, ["examples/s3-readonly.json", "--openai", "-f", "json"])
    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert data["ai_analysis"] == {"backend": "OpenAI API", "model": "gpt-5-2026-08-01", "text": "JSON review"}


def test_cli_only_one_backend():
    result = CliRunner().invoke(main, ["examples/s3-readonly.json", "--openai", "--ollama"])
    assert result.exit_code == 2
    assert "Choose one AI backend" in result.output
