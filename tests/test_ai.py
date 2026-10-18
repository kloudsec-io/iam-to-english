"""AI backends: a real local HTTP server stands in for Ollama, botocore stubs stand in for Bedrock."""

import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import boto3
import pytest
from botocore.exceptions import NoCredentialsError
from botocore.stub import Stubber
from click.testing import CliRunner

import iam_to_english.ai as ai
from iam_to_english.cli import main
from iam_to_english.errors import PolicyError

POLICY = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]}
MODEL = ai.DEFAULT_BEDROCK_MODEL


# --- Fake Ollama server ---------------------------------------------------------------------------


class FakeOllama:
    """Minimal Ollama API: GET /api/tags and POST /api/chat, with configurable behaviour."""

    def __init__(self):
        self.models = ["gemma3:4b"]
        self.chat_status = 200
        self.chat_body = None
        self.requests = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def _send(self, status, body):
                data = body if isinstance(body, bytes) else json.dumps(body).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                if self.path == "/api/tags":
                    self._send(200, {"models": [{"name": m} for m in outer.models]})
                else:
                    self._send(404, {"error": "not found"})

            def do_POST(self):
                length = int(self.headers.get("Content-Length", 0))
                payload = json.loads(self.rfile.read(length))
                outer.requests.append((self.path, payload))
                if self.path != "/api/chat":
                    self._send(404, {"error": "not found"})
                elif outer.chat_body is not None:
                    self._send(outer.chat_status, outer.chat_body)
                else:
                    self._send(200, {"message": {"role": "assistant", "content": f"answer from {payload['model']}"}})

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def ollama():
    server = FakeOllama()
    yield server
    server.close()


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_ollama_end_to_end_with_auto_selected_model(ollama):
    result = ai.analyze_with_ai(POLICY, backend="ollama", ollama_url=ollama.url + "/")  # trailing slash is fine
    assert result.model == "gemma3:4b"
    assert result.text == "answer from gemma3:4b"
    path, payload = ollama.requests[-1]
    assert path == "/api/chat"
    assert payload["stream"] is False
    assert payload["messages"][0]["role"] == "system"
    assert '"s3:GetObject"' in payload["messages"][1]["content"]


@pytest.mark.parametrize("installed,expected", [
    (["llama3.1:8b", "gemma3:4b"], "gemma3:4b"),        # preference order wins over listing order
    (["gemma3:27b", "qwen2.5:7b"], "gemma3:27b"),       # same family, other size
    (["qwen2.5:7b"], "qwen2.5:7b"),                     # anything installed beats a model that is not
    ([], ai.OLLAMA_FALLBACK_MODEL),
])
def test_ollama_model_selection(ollama, installed, expected):
    ollama.models = installed
    assert ai.resolve_ollama_model(None, ollama.url) == expected


def test_ollama_explicit_model_is_used_as_is(ollama):
    assert ai.analyze_with_ai(POLICY, backend="ollama", model_id="phi4:14b", ollama_url=ollama.url).model == "phi4:14b"


def test_ollama_missing_model_explains_how_to_pull(ollama):
    ollama.chat_status, ollama.chat_body = 404, {"error": "model 'nope' not found"}
    with pytest.raises(PolicyError) as exc:
        ai.analyze_with_ai(POLICY, backend="ollama", model_id="nope", ollama_url=ollama.url)
    assert "ollama pull nope" in exc.value.message
    assert "model 'nope' not found" in exc.value.message


@pytest.mark.parametrize("status,body,expected", [
    (500, {"error": "out of memory"}, "HTTP 500: out of memory"),
    (200, b"<html>not ollama</html>", "Unexpected response from Ollama"),
    (200, {"message": {"content": "   "}}, "returned an empty answer"),
    (200, {"done": True}, "Unexpected response from Ollama"),
])
def test_ollama_bad_responses_are_clean_errors(ollama, status, body, expected):
    ollama.chat_status, ollama.chat_body = status, body
    with pytest.raises(PolicyError) as exc:
        ai.analyze_with_ai(POLICY, backend="ollama", model_id="m", ollama_url=ollama.url)
    assert expected in exc.value.message


def test_ollama_not_running():
    url = f"http://127.0.0.1:{_free_port()}"
    with pytest.raises(PolicyError) as exc:
        ai.analyze_with_ai(POLICY, backend="ollama", ollama_url=url)
    assert "Cannot reach Ollama" in exc.value.message
    assert "ollama serve" in exc.value.message


@pytest.mark.parametrize("url", ["localhost:11434", "ftp://x", "http://", ""])
def test_ollama_invalid_url(url):
    with pytest.raises(PolicyError) as exc:
        ai.analyze_with_ai(POLICY, backend="ollama", ollama_url=url)
    assert "Invalid Ollama URL" in exc.value.message


def test_ollama_timeout(monkeypatch):
    def slow(*args, **kwargs):
        raise TimeoutError("timed out")

    monkeypatch.setattr(ai.urllib.request, "urlopen", slow)
    with pytest.raises(PolicyError) as exc:
        ai._analyze_with_ollama("msg", "big:70b", "http://localhost:11434")
    assert "did not answer within" in exc.value.message


def test_cli_ollama_end_to_end(ollama):
    result = CliRunner().invoke(main, ["examples/s3-readonly.json", "--ollama", "--ollama-url", ollama.url])
    assert result.exit_code == 0, result.output
    assert "Risk: CLEAN" in result.output
    assert "AI Analysis (Ollama - gemma3:4b)" in result.output
    assert "answer from gemma3:4b" in result.output


def test_cli_ollama_error_exits_2():
    result = CliRunner().invoke(main, ["examples/s3-readonly.json", "--ollama", "--ollama-url",
                                       f"http://127.0.0.1:{_free_port()}"])
    assert result.exit_code == 2
    assert "Cannot reach Ollama" in result.output


# --- Bedrock --------------------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def fake_aws_credentials(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.delenv("AWS_PROFILE", raising=False)
    monkeypatch.delenv("AWS_DEFAULT_REGION", raising=False)
    monkeypatch.delenv("AWS_REGION", raising=False)
    monkeypatch.setenv("AWS_CONFIG_FILE", "/nonexistent")
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", "/nonexistent")


class FakeSession:
    """Stands in for boto3.Session, handing out stubbed clients."""

    def __init__(self, region, list_profiles=None, converse=()):
        self.region_name = region
        self.control = boto3.client("bedrock", region_name=region or "us-east-1")
        self.runtime = boto3.client("bedrock-runtime", region_name=region or "us-east-1")
        self.control_stub = Stubber(self.control)
        self.runtime_stub = Stubber(self.runtime)
        if list_profiles is None:
            self.control_stub.add_client_error("list_inference_profiles", "AccessDeniedException", "denied")
        else:
            self.control_stub.add_response("list_inference_profiles", {"inferenceProfileSummaries": [
                {"inferenceProfileId": pid, "inferenceProfileName": pid, "inferenceProfileArn": "arn:aws:bedrock:x",
                 "models": [{"modelArn": "arn:aws:bedrock:us-east-1::foundation-model/m"}], "status": "ACTIVE", "type": "SYSTEM_DEFINED"} for pid in list_profiles]})
        for kind, model, payload in converse:
            if kind == "ok":
                self.runtime_stub.add_response("converse", payload, {
                    "modelId": model, "messages": _any(), "system": _any(), "inferenceConfig": _any()})
            else:
                self.runtime_stub.add_client_error("converse", kind, payload)
        self.control_stub.activate()
        self.runtime_stub.activate()

    def client(self, service, region_name=None):
        return self.control if service == "bedrock" else self.runtime


def _any():
    from botocore.stub import ANY
    return ANY


def _ok(text="bedrock says hi", stop="end_turn", extra_blocks=()):
    return {"output": {"message": {"role": "assistant", "content": [*extra_blocks, {"text": text}]}},
            "stopReason": stop, "usage": {"inputTokens": 1, "outputTokens": 1, "totalTokens": 2},
            "metrics": {"latencyMs": 1}}


def _install(monkeypatch, session):
    monkeypatch.setattr(boto3, "Session", lambda profile_name=None, region_name=None: session)


def test_bedrock_uses_listed_geo_profile(monkeypatch):
    session = FakeSession("eu-west-1", list_profiles=[f"global.{MODEL}", f"eu.{MODEL}", "eu.other"],
                          converse=[("ok", f"eu.{MODEL}", _ok())])
    _install(monkeypatch, session)
    result = ai.analyze_with_ai(POLICY, region="eu-west-1")
    assert result.model == f"eu.{MODEL}"
    assert result.text == "bedrock says hi"
    session.runtime_stub.assert_no_pending_responses()


def test_bedrock_falls_back_when_profiles_cannot_be_listed(monkeypatch):
    session = FakeSession("ap-southeast-2", list_profiles=None, converse=[
        ("ValidationException", None, "The provided model identifier is invalid."),
        ("ok", f"global.{MODEL}", _ok()),
    ])
    _install(monkeypatch, session)
    result = ai.analyze_with_ai(POLICY, region="ap-southeast-2")
    assert result.model == f"global.{MODEL}"  # apac. was tried first and rejected


def test_bedrock_region_comes_from_profile_when_not_given(monkeypatch):
    session = FakeSession("us-east-1", list_profiles=[f"us.{MODEL}"], converse=[("ok", f"us.{MODEL}", _ok())])
    _install(monkeypatch, session)
    assert ai.analyze_with_ai(POLICY).model == f"us.{MODEL}"


def test_bedrock_without_region_is_a_clear_error(monkeypatch):
    _install(monkeypatch, FakeSession(None))
    with pytest.raises(PolicyError) as exc:
        ai.analyze_with_ai(POLICY)
    assert "--ai-region" in exc.value.message


def test_bedrock_explicit_profile_id_is_not_rewritten(monkeypatch):
    session = FakeSession("eu-west-1", list_profiles=[], converse=[("ok", "eu.anthropic.claude-sonnet-x", _ok())])
    _install(monkeypatch, session)
    assert ai.analyze_with_ai(POLICY, region="eu-west-1", model_id="eu.anthropic.claude-sonnet-x").model == \
        "eu.anthropic.claude-sonnet-x"


def test_bedrock_joins_text_blocks_and_flags_truncation(monkeypatch):
    # Non-text blocks (reasoning, tool use...) can come first; only text blocks are kept
    other = {"toolUse": {"toolUseId": "t1", "name": "thinking", "input": {"note": "thinking..."}}}
    session = FakeSession("us-east-1", list_profiles=[f"us.{MODEL}"],
                          converse=[("ok", f"us.{MODEL}", _ok("final answer", "max_tokens", [other]))])
    _install(monkeypatch, session)
    text = ai.analyze_with_ai(POLICY, region="us-east-1").text
    assert text.startswith("final answer")
    assert "thinking..." not in text
    assert "truncated" in text


def test_bedrock_access_denied_explains_model_access(monkeypatch):
    session = FakeSession("us-east-1", list_profiles=[f"us.{MODEL}"],
                          converse=[("AccessDeniedException", None, "You don't have access to the model")])
    _install(monkeypatch, session)
    with pytest.raises(PolicyError) as exc:
        ai.analyze_with_ai(POLICY, region="us-east-1")
    assert "Model access" in exc.value.message


def test_bedrock_all_candidates_rejected_suggests_listing_profiles(monkeypatch):
    msg = "Invocation of model ID with on-demand throughput isn't supported."
    session = FakeSession("us-west-2", list_profiles=None, converse=[
        ("ValidationException", None, msg), ("ValidationException", None, msg), ("ValidationException", None, msg)])
    _install(monkeypatch, session)
    with pytest.raises(PolicyError) as exc:
        ai.analyze_with_ai(POLICY, region="us-west-2")
    assert "aws bedrock list-inference-profiles --region us-west-2" in exc.value.message


def test_bedrock_without_credentials(monkeypatch):
    session = FakeSession("us-east-1", list_profiles=[f"us.{MODEL}"])

    def no_creds(**kwargs):
        raise NoCredentialsError()

    session.runtime.converse = no_creds
    _install(monkeypatch, session)
    with pytest.raises(PolicyError) as exc:
        ai.analyze_with_ai(POLICY, region="us-east-1")
    assert "No AWS credentials" in exc.value.message


@pytest.mark.parametrize("region,first", [
    ("us-east-1", "us."), ("eu-central-1", "eu."), ("ap-south-1", "apac."), ("ap-northeast-1", "jp."),
    ("ap-southeast-2", "au."),
    ("us-gov-west-1", "us-gov."), ("ca-central-1", "us."), ("me-south-1", "global."),
])
def test_static_candidates(region, first):
    candidates = ai.resolve_bedrock_model_candidates(MODEL, region, session=None)
    assert candidates[0] == first + MODEL
    assert candidates[-1] == MODEL


def test_cli_bedrock_end_to_end(monkeypatch):
    session = FakeSession("eu-west-3", list_profiles=[f"eu.{MODEL}"], converse=[("ok", f"eu.{MODEL}", _ok("deep"))])
    _install(monkeypatch, session)
    result = CliRunner().invoke(main, ["examples/complex-policy.json", "--ai", "--ai-region", "eu-west-3"])
    assert result.exit_code == 0, result.output
    assert f"AI Analysis (Amazon Bedrock - eu.{MODEL})" in result.output
    assert result.output.rstrip().endswith("deep")


def test_ollama_request_bounds_output_and_fits_context(ollama):
    big = {"Version": "2012-10-17", "Statement": [
        {"Sid": f"S{i}", "Effect": "Allow", "Action": [f"s3:GetObject{i}"], "Resource": f"arn:aws:s3:::bucket-{i}/*"}
        for i in range(400)]}
    ai.analyze_with_ai(big, backend="ollama", model_id="m", ollama_url=ollama.url)
    options = ollama.requests[-1][1]["options"]
    prompt_chars = sum(len(m["content"]) for m in ollama.requests[-1][1]["messages"])
    assert options["num_predict"] == ai.OLLAMA_MAX_OUTPUT_TOKENS
    assert options["num_ctx"] * 3 >= prompt_chars + ai.OLLAMA_MAX_OUTPUT_TOKENS * 3

    assert options["num_ctx"] > 4096

    ai.analyze_with_ai(POLICY, backend="ollama", model_id="m", ollama_url=ollama.url)
    assert ollama.requests[-1][1]["options"]["num_ctx"] == 4096  # Ollama's usual default when it fits


def test_ollama_truncated_answer_is_flagged(ollama):
    ollama.chat_body = {"message": {"content": "partial"}, "done_reason": "length"}
    assert "truncated" in ai.analyze_with_ai(POLICY, backend="ollama", model_id="m", ollama_url=ollama.url).text


def test_bedrock_region_from_aws_region_env(monkeypatch):
    # boto3 ignores AWS_REGION; the tool must not
    monkeypatch.setenv("AWS_REGION", "eu-central-1")
    session = FakeSession(None, list_profiles=[f"eu.{MODEL}"], converse=[("ok", f"eu.{MODEL}", _ok())])
    _install(monkeypatch, session)
    assert ai.analyze_with_ai(POLICY).model == f"eu.{MODEL}"
